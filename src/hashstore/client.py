"""HashStore Command Line App"""
import logging
import os
from argparse import ArgumentParser
from datetime import datetime
import multiprocessing
from pathlib import Path
import yaml
import pg8000
from hashstore import HashStoreFactory


class HashStoreParser:
    """Class to setup client arguments"""

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

    def __init__(self):
        """Initialize the argparse 'parser'."""

        # Add positional argument
        self.parser.add_argument("store_path", help="Path of the HashStore")

        # Add optional arguments
        self.parser.add_argument(
            "-knbvm",
            dest="knbvm_flag",
            action="store_true",
            help="Flag for testing with knbvm",
        )
        self.parser.add_argument(
            "-chs",
            dest="create_hashstore",
            action="store_true",
            help="Create a HashStore",
        )
        self.parser.add_argument(
            "-dp", "-store_depth", dest="depth", help="Depth of HashStore"
        )
        self.parser.add_argument(
            "-wp", "-store_width", dest="width", help="Width of HashStore"
        )
        self.parser.add_argument(
            "-ap",
            "-store_algorithm",
            dest="algorithm",
            help="Algorithm to use when calculating object address",
        )
        self.parser.add_argument(
            "-nsp",
            "-store_namespace",
            dest="formatid",
            help="Default metadata namespace for metadata",
        )

        # Testing related arguments
        self.parser.add_argument(
            "-sdir",
            dest="source_directory",
            help="Source directory of objects to work with",
        )
        self.parser.add_argument(
            "-stype",
            dest="source_directory_type",
            help="Source directory type (ex. 'objects' or 'metadata')",
        )
        self.parser.add_argument(
            "-nobj",
            dest="num_obj_to_convert",
            help="Number of objects to convert",
        )
        self.parser.add_argument(
            "-sts",
            dest="store_to_hashstore",
            action="store_true",
            help="Retrieve and validate objects in HashStore",
        )
        self.parser.add_argument(
            "-rav",
            dest="retrieve_and_validate",
            action="store_true",
            help="Retrieve and validate objects in HashStore",
        )
        self.parser.add_argument(
            "-dfs",
            dest="delete_from_hashstore",
            action="store_true",
            help="Retrieve and validate objects in HashStore",
        )

        # Individual API call related arguments
        self.parser.add_argument(
            "-pid",
            dest="object_pid",
            help="Pid/Guid of object to work with",
        )
        self.parser.add_argument(
            "-path",
            dest="object_path",
            help="Path of the data or metadata object",
        )
        self.parser.add_argument(
            "-algo",
            dest="object_algorithm",
            help="Algorithm to work with",
        )
        self.parser.add_argument(
            "-checksum",
            dest="object_checksum",
            help="Checksum of data object to validate",
        )
        self.parser.add_argument(
            "-checksum_algo",
            dest="object_checksum_algorithm",
            help="Algorithm of checksum to validate",
        )
        self.parser.add_argument(
            "-obj_size",
            dest="object_size",
            help="Size of data object to validate",
        )
        self.parser.add_argument(
            "-formatid",
            dest="object_formatid",
            help="Format/namespace of the metadata",
        )
        # Public API Flags
        self.parser.add_argument(
            "-getchecksum",
            dest="client_getchecksum",
            action="store_true",
            help="Flag to get the hex digest of a data object in HashStore",
        )
        self.parser.add_argument(
            "-storeobject",
            dest="client_storeobject",
            action="store_true",
            help="Flag to store an object to a HashStore",
        )
        self.parser.add_argument(
            "-storemetadata",
            dest="client_storemetadata",
            action="store_true",
            help="Flag to store a metadata document to a HashStore",
        )
        self.parser.add_argument(
            "-deleteobject",
            dest="client_deleteobject",
            action="store_true",
            help="Flag to delete on object from a HashStore",
        )
        self.parser.add_argument(
            "-deletemetadata",
            dest="client_deletemetadata",
            action="store_true",
            help="Flag to dlete a metadata document from a HashStore",
        )

    def load_store_properties(self, hashstore_yaml):
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
                "HashStoreParser - load_store_properties: hashstore.yaml not found"
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

    def get_parser_args(self):
        """Get command line arguments"""
        return self.parser.parse_args()


class HashStoreClient:
    """Create a HashStore to use through the command line."""

    def __init__(self, properties, testflag=None):
        """Initialize HashStore and MetacatDB

        Args:
            properties: See FileHashStore for dictionary example
            testflag (str): "knbvm" to initialize MetacatDB
        """
        factory = HashStoreFactory()

        # Get HashStore from factory
        module_name = "filehashstore"
        class_name = "FileHashStore"

        # Instance attributes
        self.hashstore = factory.get_hashstore(module_name, class_name, properties)
        logging.info("HashStoreClient - HashStore initialized.")

        # Setup access to Metacat postgres db
        if testflag:
            self.metacatdb = MetacatDB(properties["store_path"], self.hashstore)
            logging.info("HashStoreClient - MetacatDB initialized.")

    # Methods relating to testing HashStore with knbvm (test.arcticdata.io)

    def store_to_hashstore_from_list(self, origin_dir, obj_type, num):
        """Store objects in a given directory into HashStore

        Args:
            origin_dir (str): Directory to convert
            obj_type (str): 'object' or 'metadata'
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
        pool = multiprocessing.Pool()

        # Call 'obj_type' respective public API methods
        info_msg = f"HashStoreClient - Request to Store {len(checked_obj_list)} Objs"
        logging.info(info_msg)
        if obj_type == "object":
            # results = pool.starmap(self.hashstore.store_object, checked_obj_list)
            pool.imap(self.try_store_object, checked_obj_list)
        # TODO: if obj_type == "metadata":

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

    def try_store_object(self, obj_tuple):
        """Store an object to HashStore and log exceptions as warning.

        Args:
            obj_tuple: See HashStore store_object signature for details.
        """
        try:
            return self.hashstore.store_object(*obj_tuple)
        except Exception as so_exception:
            logging.warning(so_exception)

    def retrieve_and_validate_from_hashstore(self, origin_dir, obj_type, num):
        """Retrieve objects or metadata from a Hashstore and validate the content.

        Args:
            origin_dir (str): Directory to convert
            obj_type (str): 'object' or 'metadata'
            num (int): Number of files to store
        """
        logging.info("HashStore Client - Begin retrieving and validating objects.")
        checked_num_of_files = None
        # Check number of files to store
        if num is not None:
            checked_num_of_files = int(num)

        # Object and Metadata list
        metacat_obj_list = self.metacatdb.get_object_metadata_list(
            origin_dir, checked_num_of_files
        )

        # Get list of objects to store from metacat db
        logging.info("HashStore Client - Refining object list for %s", obj_type)
        if obj_type == "object":
            checked_obj_list = self.metacatdb.refine_list_for_objects(
                metacat_obj_list, "retrieve"
            )
        if obj_type == "metadata":
            checked_obj_list = self.metacatdb.refine_list_for_metadata(metacat_obj_list)

        start_time = datetime.now()

        # Setup pool and processes
        pool = multiprocessing.Pool()
        if obj_type == "object":
            pool.map(self.validate_object, checked_obj_list)
        # TODO: if obj_type == "metadata":

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

    def validate_object(self, obj_tuple):
        """Retrieves an object from HashStore and validates its checksum.

        Args:
            obj_tuple: pid_guid, obj_checksum_algo, obj_checksum
        """
        pid_guid = obj_tuple[0]
        algo = obj_tuple[1]
        obj_db_checksum = obj_tuple[2]

        with self.hashstore.retrieve_object(pid_guid) as obj_stream:
            computed_digest = self.hashstore.computehash(obj_stream, algo)
            obj_stream.close()

        if digest != obj_db_checksum:
            err_msg = (
                f"Assertion Error for pid/guid: {pid_guid} -"
                + f" Digest calculated from stream ({computed_digest}) does not match"
                + f" checksum from metacat db: {obj_db_checksum}"
            )
            logging.error(err_msg)
            print(err_msg)

        return

    def delete_objects_from_list(self, origin_dir, obj_type, num):
        """Store objects in a given directory into HashStore
        Args:
            origin_dir (str): Directory to convert
            obj_type (str): 'object' or 'metadata'
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
                metacat_obj_list, "delete"
            )
        if obj_type == "metadata":
            checked_obj_list = self.metacatdb.refine_list_for_metadata(metacat_obj_list)

        start_time = datetime.now()

        # Setup pool and processes
        pool = multiprocessing.Pool()

        # Call 'obj_type' respective public API methods
        info_msg = f"HashStoreClient - Request to delete {len(checked_obj_list)} Objs"
        logging.info(info_msg)
        if obj_type == "object":
            # results = pool.starmap(self.hashstore.store_object, checked_obj_list)
            pool.imap(self.try_delete_object, checked_obj_list)
        # TODO: if obj_type == "metadata":

        # Close the pool and wait for all processes to complete
        pool.close()
        pool.join()

        end_time = datetime.now()
        content = (
            f"HashStoreClient (delete_objects_from_list):\n"
            f"Start Time: {start_time}\nEnd Time: {end_time}\n"
            + f"Total Time to Store {len(checked_obj_list)} {obj_type}"
            + f" Objects: {end_time - start_time}\n"
        )
        logging.info(content)

    def try_delete_object(self, obj_pid):
        """Delete an object to HashStore and log exceptions as warning."""
        try:
            return self.hashstore.delete_object(obj_pid)
        except Exception as do_exception:
            logging.warning(do_exception)


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

        # Note, 'pgdb.yaml' config file must be manually created for security
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
        """Query the metacat db for the full obj and metadata list and order by guid.

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
                ON identifier.guid = systemmetadata.guid ORDER BY identifier.guid{limit_query};"""
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
            row_checksum = row[4]
            row_checksum_algorithm = row[5]
            tuple_item = (
                pid_guid,
                metadatapath_docid_rev,
                metadata_namespace,
                row_checksum,
                row_checksum_algorithm,
            )
            object_metadata_list.append(tuple_item)

        # Close the cursor and connection when done
        cursor.close()
        conn.close()

        return object_metadata_list

    def refine_list_for_objects(self, metacat_obj_list, action):
        """Refine a list of objects by checking for file existence and removing duplicates.

        Args:
            metacat_obj_list (List): List of tuple objects representing rows from metacat db
            action (string): "store" or "retrieve".
                "store" will create a list of objects to store that do not exist in HashStore.
                "retrieve" will create a list of objects (tuples) that exist in HashStore.
                "delete" will create a list of object pids

        Returns:
            refined_object_list (List): List of tuple objects based on "action"
        """
        refined_object_list = []
        for tuple_item in metacat_obj_list:
            pid_guid = tuple_item[0]
            filepath_docid_rev = tuple_item[1]
            item_checksum = tuple_item[3]
            item_checksum_algorithm = tuple_item[4]
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
                            item_checksum,
                            item_checksum_algorithm,
                        )
                        refined_object_list.append(store_object_tuple_item)
                if action == "retrieve":
                    if self.hashstore.exists(
                        "objects", self.hashstore.get_sha256_hex_digest(pid_guid)
                    ):
                        retrieve_object_tuple_item = (
                            pid_guid,
                            item_checksum_algorithm,
                            item_checksum,
                        )
                        refined_object_list.append(retrieve_object_tuple_item)
                if action == "delete":
                    if self.hashstore.exists(
                        "objects", self.hashstore.get_sha256_hex_digest(pid_guid)
                    ):
                        refined_object_list.append(pid_guid)

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


if __name__ == "__main__":
    # Parse arguments
    parser = HashStoreParser()
    args = parser.get_parser_args()

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

    # Client setup process
    # Can't use client app without first initializing HashStore
    store_path = getattr(args, "store_path")
    store_path_config_yaml = store_path + "/hashstore.yaml"
    if not os.path.exists(store_path_config_yaml):
        raise FileNotFoundError(
            f"Missing config file (hashstore.yaml) at store path: {store_path}."
            + " HashStore must first be initialized, use `--help` for more information."
        )
    # Setup logging
    # Create log file if it doesn't already exist
    hashstore_py_log = store_path + "/python_hashstore.log"
    python_log_file_path = Path(hashstore_py_log)
    if not os.path.exists(python_log_file_path):
        python_log_file_path.parent.mkdir(parents=True, exist_ok=True)
        open(python_log_file_path, "w", encoding="utf-8").close()
    logging.basicConfig(
        filename=python_log_file_path,
        level=logging.WARNING,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # Instantiate HashStore Client
    props = parser.load_store_properties(store_path_config_yaml)
    hs = HashStoreClient(props, getattr(args, "knbvm_flag"))

    # HashStore client entry point
    if getattr(args, "source_directory") is not None:
        directory_to_convert = getattr(args, "source_directory")
        # Check if the directory to convert exists
        if os.path.exists(directory_to_convert):
            # If -nobj is supplied, limit the objects we work with
            number_of_objects_to_convert = getattr(args, "num_obj_to_convert")
            # Determine if we are working with objects or metadata
            directory_type = getattr(args, "source_directory_type")
            accepted_directory_types = ["object", "metadata"]
            if directory_type not in accepted_directory_types:
                raise ValueError(
                    "Directory `-stype` cannot be empty, must be 'object' or 'metadata'."
                    + f" source_directory_type: {directory_type}"
                )
            if getattr(args, "store_to_hashstore"):
                hs.store_to_hashstore_from_list(
                    directory_to_convert,
                    directory_type,
                    number_of_objects_to_convert,
                )
            if getattr(args, "retrieve_and_validate"):
                hs.retrieve_and_validate_from_hashstore(
                    directory_to_convert,
                    directory_type,
                    number_of_objects_to_convert,
                )
            if getattr(args, "delete_from_hashstore"):
                hs.delete_objects_from_list(
                    directory_to_convert,
                    directory_type,
                    number_of_objects_to_convert,
                )

        else:
            raise FileNotFoundError(
                f"Directory to convert does not exist: {getattr(args, 'convert_directory')}."
            )
    # Calculate the hex digest of a given pid with algorithm supplied
    elif (
        getattr(args, "client_getchecksum")
        and getattr(args, "object_pid") is not None
        and getattr(args, "object_algorithm") is not None
    ):
        pid = getattr(args, "object_pid")
        algorithm = getattr(args, "object_algorithm")
        digest = hs.hashstore.get_hex_digest(pid, algorithm)
        print(f"guid/pid: {pid}")
        print(f"algorithm: {algorithm}")
        print(f"Checksum/Hex Digest: {digest}")
    # Store object to HashStore
    elif (
        getattr(args, "client_storeobject")
        and getattr(args, "object_pid") is not None
        and getattr(args, "object_path") is not None
    ):
        pid = getattr(args, "object_pid")
        path = getattr(args, "object_path")
        algorithm = getattr(args, "object_algorithm")
        checksum = getattr(args, "checksum")
        checksum_algorithm = getattr(args, "checksum_algo")
        size = getattr(args, "object_size")
        object_info_tuple = (pid, path, algorithm, checksum, checksum_algorithm, size)
        object_metadata = hs.hashstore.store_object(*object_info_tuple)
        print(f"Object Metadata:\n{object_metadata}")
    # Store metadata to HashStore
    elif (
        getattr(args, "client_metadata")
        and getattr(args, "object_pid") is not None
        and getattr(args, "object_path") is not None
    ):
        pid = getattr(args, "object_pid")
        path = getattr(args, "object_path")
        formatid = getattr(args, "object_formatid")
        metadata_cid = hs.hashstore.store_metadata(pid, path, formatid)
        print(f"Metadata ID: {metadata_cid}")
    # Delete object from HashStore
    elif (
        getattr(args, "client_deleteobject") and getattr(args, "object_pid") is not None
    ):
        pid = getattr(args, "object_pid")
        delete_status = hs.hashstore.delete_object(pid)
        if delete_status:
            print("Object for pid: {pid} has been deleted.")
    # Delete metadata from HashStore
    elif (
        getattr(args, "client_deletemetadata")
        and getattr(args, "object_pid") is not None
        and getattr(args, "object_formatid") is not None
    ):
        pid = getattr(args, "object_pid")
        formatid = getattr(args, "object_formatid")
        delete_status = hs.hashstore.delete_metadata(pid, formatid)
        if delete_status:
            print("Metadata for pid: {pid} with formatid: {formatid} has been deleted.")
