"""HashStore Command Line App"""
import logging
import os
from argparse import ArgumentParser
from datetime import datetime
import multiprocessing
import yaml
import pg8000
from hashstore import HashStoreFactory


class HashStoreClient:
    """Create a HashStore Client to use through the command line."""

    def __init__(self, properties):
        """Initialize HashStore and MetacatDB adapters"""
        factory = HashStoreFactory()

        # Get HashStore from factory
        module_name = "filehashstore"
        class_name = "FileHashStore"

        # Class variables
        self.hashstore = factory.get_hashstore(module_name, class_name, properties)
        self.metacatdb = MetacatDB(properties["store_path"], self.hashstore)

    def store_to_hashstore_from_list(self, origin_dir, obj_type, num):
        """Store objects in a given directory into HashStore

        Args:
            origin_dir (str): Directory to convert
            obj_type (str): 'object' or 'metadata'
            config_yaml (str): Path to HashStore config file `hashstore.yaml`
            num (int): Number of files to store
        """
        # Get list of files from directory
        file_list = os.listdir(origin_dir)
        checked_num_of_files = len(file_list)
        # Check number of files to store
        if num is not None:
            checked_num_of_files = int(num)

        # Object and Metadata list
        metacat_obj_list = self.metacatdb.get_object_metadata_list(
            origin_dir, checked_num_of_files
        )

        # Get list of objects to store from metacat db
        if obj_type == "object":
            checked_obj_list = self.metacatdb.refine_list_for_objects(
                metacat_obj_list, "store"
            )
        if obj_type == "metadata":
            checked_obj_list = self.metacatdb.refine_list_for_metadata(metacat_obj_list)

        start_time = datetime.now()

        # Setup pool and processes
        # num_processes = os.cpu_count() - 2
        # pool = multiprocessing.Pool(processes=num_processes)
        pool = multiprocessing.Pool()

        # Call 'obj_type' respective public API methods
        if obj_type == "object":
            logging.info("Storing objects")
            results = pool.starmap(self.hashstore.store_object, checked_obj_list)
        if obj_type == "metadata":
            logging.info("Storing metadata")
            results = pool.starmap(self.hashstore.store_metadata, checked_obj_list)

        # Log exceptions
        cleanup_msg = "Checking results and logging exceptions"
        print(cleanup_msg)
        logging.info(cleanup_msg)
        for result in results:
            if isinstance(result, Exception):
                print(result)
                logging.error(result)

        # Close the pool and wait for all processes to complete
        pool.close()
        pool.join()

        end_time = datetime.now()
        content = (
            f"HashStoreClient (store_to_hashstore_from_list):\n"
            f"Start Time: {start_time}\nEnd Time: {end_time}\n"
            + f"Total Time to Store {len(checked_obj_list)} {obj_type}"
            + f" Objects: {end_time - start_time}\n"
        )
        logging.info(content)

    def retrieve_and_validate_from_hashstore(self, origin_dir, obj_type, num):
        """Retrieve objects or metadata from a Hashstore and validate the content."""
        checked_num_of_files = None
        # Check number of files to store
        if num is not None:
            checked_num_of_files = int(num)

        # Object and Metadata list
        metacat_obj_list = self.metacatdb.get_object_metadata_list(
            origin_dir, checked_num_of_files
        )

        # Get list of objects to store from metacat db
        if obj_type == "object":
            checked_obj_list = self.metacatdb.refine_list_for_objects(
                metacat_obj_list, "retrieve"
            )
        if obj_type == "metadata":
            checked_obj_list = self.metacatdb.refine_list_for_metadata(metacat_obj_list)

        start_time = datetime.now()

        # Setup pool and processes
        # pool = multiprocessing.Pool()
        # num_processes = os.cpu_count() - 2
        # pool = multiprocessing.Pool(processes=num_processes)

        # https://pythonspeed.com/articles/python-multiprocessing/
        multiprocessing.set_start_method("spawn")
        with multiprocessing.get_context("spawn").Pool() as pool:
            if obj_type == "object":
                results = pool.map(self.validate, checked_obj_list)
        # if obj_type == "metadata":
        # TODO

        # Log exceptions
        cleanup_msg = "Checking results and logging exceptions"
        print(cleanup_msg)
        logging.info(cleanup_msg)
        for result in results:
            if isinstance(result, Exception):
                print(result)
                logging.error(result)

        # Close the pool and wait for all processes to complete
        pool.close()
        pool.join()

        end_time = datetime.now()
        content = (
            f"retrieve_and_validate_from_hashstore:\n"
            f"Start Time: {start_time}\nEnd Time: {end_time}\n"
            + f"Total Time to retrieve and validate {len(checked_obj_list)} {obj_type}"
            + f" Objects: {end_time - start_time}\n"
        )
        logging.info(content)

    def validate(self, obj_tuple):
        """Retrieve and validate a list of objects."""
        pid_guid = obj_tuple[0]
        algo = obj_tuple[4]
        checksum = obj_tuple[3]
        with self.hashstore.retrieve_object(pid_guid) as obj_stream:
            digest = self.hashstore.computehash(obj_stream, algo)
            obj_stream.close()

        # Check algorithm
        print(f"Validating pid: {pid_guid}")
        if digest != checksum:
            err_msg = (
                f"Assertion Error for pid/guid: {pid_guid} -"
                + f" Digest calculated from stream ({digest}) does not match"
                + f" checksum from metacat db: {checksum}"
            )
            logging.error(err_msg)
            print(err_msg)
        else:
            info_msg = f"Checksums match for pid/guid: {pid_guid}!"
            print(info_msg)

    def get_obj_hex_digest_from_store(self, pid_guid, obj_algo):
        """Given a pid and algorithm, get the hex digest of the object"""
        digest = self.hashstore.get_hex_digest(pid, algorithm)
        print(f"guid/pid: {pid_guid}")
        print(f"algorithm: {obj_algo}")
        print(f"digest: {digest}")


class MetacatDB:
    """Class to interact with Metacat's Postgres DB"""

    def __init__(self, hashstore_path, hashstore):
        """Initialize credentials to access metacat pgdb."""
        db_keys = [
            "db_user",
            "db_password",
            "db_host",
            "db_port",
            "db_name",
        ]

        pgyaml_path = hashstore_path + "/pgdb.yaml"
        if not os.path.exists(pgyaml_path):
            exception_string = (
                "HashStore CLI Client - _load_metacat_db_properties: pgdb.yaml not found"
                + " in store root path. Must be manually created with the following keys:"
                + " db_user, db_password, db_host, db_port, db_name"
            )
            raise FileNotFoundError(exception_string)
        # Open file
        with open(pgyaml_path, "r", encoding="utf-8") as file:
            yaml_data = yaml.safe_load(file)

        # Get database values
        self.hashstore = hashstore
        self.db_yaml_dict = {}
        for key in db_keys:
            checked_property = yaml_data[key]
            self.db_yaml_dict[key] = checked_property

    def get_object_metadata_list(self, origin_directory, num):
        """Query the metacat db for the full obj and metadata list.

        Args:
            origin_directory (string): 'var/metacat/data' or 'var/metacat/documents'
            num (int): Number of rows to retrieve from metacat db
        """
        # Create a connection to the database
        db_user = self.db_yaml_dict["db_user"]
        db_password = self.db_yaml_dict["db_password"]
        db_host = self.db_yaml_dict["db_host"]
        db_port = self.db_yaml_dict["db_port"]
        db_name = self.db_yaml_dict["db_name"]

        conn = pg8000.connect(
            user=db_user,
            password=db_password,
            host=db_host,
            port=int(db_port),
            database=db_name,
        )

        # Create a cursor to execute queries
        cursor = conn.cursor()

        # Query to refine rows between `identifier` and `systemmetadata`` table
        if num is None:
            limit_query = ""
        else:
            limit_query = f" LIMIT {num}"
        query = f"""SELECT identifier.guid, identifier.docid, identifier.rev,
                systemmetadata.object_format, systemmetadata.checksum,
                systemmetadata.checksum_algorithm FROM identifier INNER JOIN systemmetadata
                ON identifier.guid = systemmetadata.guid{limit_query};"""
        cursor.execute(query)

        # Fetch all rows from the result set
        rows = cursor.fetchall()

        # Create full object list to store into HashStore
        print("Creating list of objects and metadata from metacat db")
        object_metadata_list = []
        for row in rows:
            # Get pid, filepath and formatId
            pid_guid = row[0]
            metadatapath_docid_rev = origin_directory + "/" + row[1] + "." + str(row[2])
            metadata_namespace = row[3]
            checksum = row[4]
            checksum_algorithm = row[5]
            tuple_item = (
                pid_guid,
                metadatapath_docid_rev,
                metadata_namespace,
                checksum,
                checksum_algorithm,
            )
            object_metadata_list.append(tuple_item)

        # Close the cursor and connection when done
        cursor.close()
        conn.close()

        return object_metadata_list

    def refine_list_for_objects(self, metacat_obj_list, action):
        """Refine a list of objects by checking for file existence and removing duplicates.

        Args:
            store (HashStore): HashStore object
            metacat_obj_list (List): List of tuple objects representing rows from metacat db
            action (string): "store" or "retrieve".
                "store" will create a list of objects to store that do not exist in HashStore.
                "retrieve" will create a list of objects that exist in HashStore.

        Returns:
            refine_list (List): List of tuple objects based on "action"
        """
        refined_object_list = []
        for tuple_item in metacat_obj_list:
            pid_guid = tuple_item[0]
            filepath_docid_rev = tuple_item[1]
            checksum = tuple_item[3]
            checksum_algorithm = tuple_item[4]
            if os.path.exists(filepath_docid_rev):
                if action == "store":
                    # If the file has already been stored, skip it
                    if not self.hashstore.exists(
                        "objects", self.hashstore.get_sha256_hex_digest(pid_guid)
                    ):
                        # This tuple is formed to match 'HashStore' store_object's signature
                        # Which is '.starmap()'ed when called
                        store_object_tuple_item = (
                            pid_guid,
                            filepath_docid_rev,
                            None,
                            checksum,
                            checksum_algorithm,
                        )
                        refined_object_list.append(store_object_tuple_item)
                if action == "retrieve":
                    print(f"Checking for pid: {pid_guid} in HashStore")
                    if self.hashstore.exists(
                        "objects", self.hashstore.get_sha256_hex_digest(pid_guid)
                    ):
                        refined_object_list.append(tuple_item)
                        print("Found! Adding to refined list")

        return refined_object_list

    def refine_list_for_metadata(self, metacat_obj_list):
        """Refine a list of metadata by checking for file existence and removing duplicates."""
        refined_metadta_list = []
        for obj in metacat_obj_list:
            pid_guid = obj[0]
            filepath_docid_rev = obj[1]
            metadata_namespace = obj[2]
            if os.path.exists(filepath_docid_rev):
                # If the file has already been stored, skip it
                if not self.hashstore.exists(
                    "metadata", self.hashstore.get_sha256_hex_digest(pid_guid)
                ):
                    tuple_item = (pid_guid, metadata_namespace, filepath_docid_rev)
                    refined_metadta_list.append(tuple_item)
        return refined_metadta_list


def _add_client_optional_arguments(argp):
    """Adds the optional arguments for the HashStore Client.

    Args:
        argp (parser): argparse Parser object

    """
    argp.add_argument(
        "-chs",
        dest="create_hashstore",
        action="store_true",
        help="Create a HashStore",
    )
    argp.add_argument("-dp", "-store_depth", dest="depth", help="Depth of HashStore")
    argp.add_argument("-wp", "-store_width", dest="width", help="Width of HashStore")
    argp.add_argument(
        "-ap",
        "-store_algorithm",
        dest="algorithm",
        help="Algorithm to use when calculating object address",
    )
    argp.add_argument(
        "-nsp",
        "-store_namespace",
        dest="formatid",
        help="Default metadata namespace for metadata",
    )

    # Directory to convert into a HashStore
    argp.add_argument(
        "-cvd",
        dest="convert_directory",
        help="Directory of objects to convert to a HashStore",
    )
    argp.add_argument(
        "-cvt",
        dest="convert_directory_type",
        help="Type of directory to convert (ex. 'objects' or 'metadata')",
    )
    argp.add_argument(
        "-nobj",
        dest="num_obj_to_convert",
        help="Number of objects to convert",
    )
    argp.add_argument(
        "-rav",
        dest="retrieve_and_validate",
        action="store_true",
        help="Retrieve and validate objects in HashStore",
    )

    # Individual API calls
    argp.add_argument(
        "-pid",
        dest="object_pid",
        help="Pid/Guid of object to work with",
    )
    argp.add_argument(
        "-algo",
        dest="object_algorithm",
        help="Algorithm to work with",
    )


def _load_store_properties(hashstore_yaml):
    """Get and return the contents of the current HashStore configuration.

    Returns:
        hashstore_yaml_dict (dict): HashStore properties with the following keys (and values):
            store_path (str): Path to the HashStore directory.
            store_depth (int): Depth when sharding an object's hex digest.
            store_width (int): Width of directories when sharding an object's hex digest.
            store_algorithm (str): Hash algorithm used for calculating the object's hex digest.
            store_metadata_namespace (str): Namespace for the HashStore's system metadata.
    """
    property_required_keys = [
        "store_path",
        "store_depth",
        "store_width",
        "store_algorithm",
        "store_metadata_namespace",
    ]

    if not os.path.exists(hashstore_yaml):
        exception_string = (
            "HashStore CLI Client - _load_store_properties: hashstore.yaml not found"
            + " in store root path."
        )
        raise FileNotFoundError(exception_string)
    # Open file
    with open(hashstore_yaml, "r", encoding="utf-8") as file:
        yaml_data = yaml.safe_load(file)

    # Get hashstore properties
    hashstore_yaml_dict = {}
    for key in property_required_keys:
        checked_property = yaml_data[key]
        if key == "store_depth" or key == "store_width":
            checked_property = int(yaml_data[key])
        hashstore_yaml_dict[key] = checked_property
    return hashstore_yaml_dict


if __name__ == "__main__":
    PROGRAM_NAME = "HashStore Command Line Client"
    DESCRIPTION = (
        "A command-line tool to convert a directory of data objects"
        + " into a hashstore and perform operations to store, retrieve,"
        + " and delete the objects."
    )
    EPILOG = "Created for DataONE (NCEAS)"
    parser = ArgumentParser(
        prog=PROGRAM_NAME,
        description=DESCRIPTION,
        epilog=EPILOG,
    )
    ### Add Positional and Optional Arguments
    parser.add_argument("store_path", help="Path of the HashStore")
    _add_client_optional_arguments(parser)

    # Client entry point
    args = parser.parse_args()

    ### Initialize Logging
    python_log_file_path = getattr(args, "store_path") + "/python_store.log"
    logging.basicConfig(
        filename=python_log_file_path,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if getattr(args, "create_hashstore"):
        # Create HashStore if -chs flag is true in a given directory
        # Get store attributes, HashStore will validate properties
        props = {
            "store_path": getattr(args, "store_path"),
            "store_depth": int(getattr(args, "depth")),
            "store_width": int(getattr(args, "width")),
            "store_algorithm": getattr(args, "algorithm"),
            "store_metadata_namespace": getattr(args, "formatid"),
        }
        HashStoreClient(props)

    else:
        # Initialize HashStore
        store_path = getattr(args, "store_path")
        store_path_config_yaml = store_path + "/hashstore.yaml"
        props = _load_store_properties(store_path_config_yaml)
        hs = HashStoreClient(props)

        if getattr(args, "convert_directory") is not None:
            directory_to_convert = getattr(args, "convert_directory")
            # Check if the directory to convert exists
            if os.path.exists(directory_to_convert):
                # If -nobj is supplied, limit the objects we work with
                number_of_objects_to_convert = getattr(args, "num_obj_to_convert")
                # Determine if we are working with objects or metadata
                directory_type = getattr(args, "convert_directory_type")
                accepted_directory_types = ["object", "metadata"]
                if directory_type not in accepted_directory_types:
                    raise ValueError(
                        "Directory `-cvt` cannot be empty, must be 'object' or 'metadata'."
                        + f" convert_directory_type: {directory_type}"
                    )
                # HashStore can only be called if a configuration file is present
                if os.path.exists(store_path_config_yaml):
                    if getattr(args, "retrieve_and_validate"):
                        hs.retrieve_and_validate_from_hashstore(
                            directory_to_convert,
                            directory_type,
                            number_of_objects_to_convert,
                        )
                    else:
                        hs.store_to_hashstore_from_list(
                            directory_to_convert,
                            directory_type,
                            number_of_objects_to_convert,
                        )
                else:
                    # If HashStore does not exist, raise exception
                    # Calling app must create HashStore first before calling methods
                    raise FileNotFoundError(
                        f"Missing config file (hashstore.yaml) at store path: {store_path}."
                        + " HashStore must be initialized, use `--help` for more information."
                    )
            else:
                raise FileNotFoundError(
                    f"Directory to convert does not exist: {getattr(args, 'convert_directory')}."
                )

        elif (
            getattr(args, "object_pid") is not None
            and getattr(args, "object_algorithm") is not None
        ):
            # Calculate the hex digest of a given pid with algorithm supplied
            pid = getattr(args, "object_pid")
            algorithm = getattr(args, "object_algorithm")

            if os.path.exists(store_path_config_yaml):
                hs.get_obj_hex_digest_from_store(pid, algorithm)
            else:
                # Calling app must initialize HashStore first before calling methods
                raise FileNotFoundError(
                    f"Missing config file (hashstore.yaml) at store path: {store_path}."
                    + " HashStore must be initialized, use `--help` for more information."
                )
