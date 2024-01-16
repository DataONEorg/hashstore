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
    """Class to set up parsing arguments via argparse."""

    def __init__(self):
        """Initialize the argparse 'parser'."""

        program_name = "HashStore Command Line Client"
        description = (
            "Command line tool to call store, retrieve and delete with a HashStore."
            + " Additionally, methods are available to test functionality with a"
            + " metacat postgres db."
        )
        epilog = "Created for DataONE (NCEAS)"

        self.parser = ArgumentParser(
            prog=program_name,
            description=description,
            epilog=epilog,
        )

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
            "-loglevel",
            dest="logging_level",
            help="Set logging level for the client",
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

        # KNBVM testing related arguments
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
            help="Store objects into a HashStore",
        )
        self.parser.add_argument(
            "-rav",
            dest="retrieve_and_validate",
            action="store_true",
            help="Retrieve and validate objects in a HashStore",
        )
        self.parser.add_argument(
            "-dfs",
            dest="delete_from_hashstore",
            action="store_true",
            help="Delete objects in a HashStore",
        )
        self.parser.add_argument(
            "-gbskip",
            dest="gb_file_size_to_skip",
            help="Number of objects to convert",
        )

        # Individual API call related optional arguments
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

        # Public API optional arguments
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
            "-retrieveobject",
            dest="client_retrieveobject",
            action="store_true",
            help="Flag to retrieve an object from a HashStore",
        )
        self.parser.add_argument(
            "-retrievemetadata",
            dest="client_retrievemetadata",
            action="store_true",
            help="Flag to retrieve a metadata document from a HashStore",
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
            help="Flag to delete a metadata document from a HashStore",
        )

    def load_store_properties(self, hashstore_yaml):
        """Get and return the contents of the current HashStore config file.

        :return: HashStore properties with the following keys (and values):
            - store_depth (int): Depth when sharding an object's hex digest.
            - store_width (int): Width of directories when sharding an object's hex digest.
            - store_algorithm (str): Hash algorithm used for calculating the object's hex digest.
            - store_metadata_namespace (str): Namespace for the HashStore's system metadata.
        :rtype: dict
        """
        property_required_keys = [
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
        """Get command line arguments."""
        return self.parser.parse_args()


class HashStoreClient:
    """Create a HashStore to use through the command line."""

    OBJ_TYPE = "object"
    MET_TYPE = "metadata"

    def __init__(self, properties, testflag=None):
        """Store objects in a given directory into HashStore.

        :param str origin_dir: Directory to convert.
        :param str obj_type: Type of objects ('object' or 'metadata').
        :param int num: Number of files to store.
        """
        factory = HashStoreFactory()

        # Get HashStore from factory
        module_name = "filehashstore"
        class_name = "FileHashStore"

        # Instance attributes
        self.hashstore = factory.get_hashstore(module_name, class_name, properties)
        logging.info("HashStoreClient - HashStore initialized.")

        # Set up access to Metacat postgres db
        if testflag:
            self.metacatdb = MetacatDB(properties["store_path"], self.hashstore)
            logging.info("HashStoreClient - MetacatDB initialized.")

    # Methods relating to testing HashStore with knbvm (test.arcticdata.io)

    def store_to_hashstore_from_list(self, origin_dir, obj_type, num, skip_obj_size):
        """Store objects in a given directory into HashStore.

        :param str origin_dir: Directory to convert.
        :param str obj_type: Type of objects ('object' or 'metadata').
        :param int num: Number of files to store.
        :param int skip_obj_size: Size of obj in GB to skip (ex. 4 = 4GB)
        """
        info_msg = f"HashStoreClient - Begin storing {obj_type} objects."
        logging.info(info_msg)
        # Object and Metadata list
        metacat_obj_list = self.metacatdb.get_object_metadata_list(
            origin_dir, num, skip_obj_size
        )
        logging.info(info_msg)

        # Get list of objects to store from metacat db
        if obj_type == self.OBJ_TYPE:
            checked_obj_list = self.metacatdb.refine_list_for_objects(
                metacat_obj_list, "store"
            )
        if obj_type == self.MET_TYPE:
            checked_obj_list = self.metacatdb.refine_list_for_metadata(
                metacat_obj_list, "store"
            )

        start_time = datetime.now()

        # Set up pool and processes
        pool = multiprocessing.Pool()

        # Call 'obj_type' respective public API methods
        info_msg = f"HashStoreClient - Request to Store {len(checked_obj_list)} Objs"
        logging.info(info_msg)
        if obj_type == self.OBJ_TYPE:
            # results = pool.starmap(self.hashstore.store_object, checked_obj_list)
            pool.imap(self.try_store_object, checked_obj_list)
        if obj_type == self.MET_TYPE:
            pool.imap(self.try_store_metadata, checked_obj_list)

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

        :param obj_tuple: See HashStore store_object signature for details.
        """
        try:
            self.hashstore.store_object(*obj_tuple)
            return
        # pylint: disable=W0718
        except Exception as so_exception:
            print(so_exception)

    def try_store_metadata(self, obj_tuple):
        """Store a metadata document to HashStore and log exceptions as warning.

        Args:
            obj_tuple: See HashStore store_metadata signature for details.
        """
        try:
            self.hashstore.store_metadata(*obj_tuple)
            return
        # pylint: disable=W0718
        except Exception as so_exception:
            print(so_exception)

    def retrieve_and_validate_from_hashstore(
        self, origin_dir, obj_type, num, skip_obj_size
    ):
        """Retrieve objects or metadata from a Hashstore and validate the content.

        :param str origin_dir: Directory to convert.
        :param str obj_type: Type of objects ('object' or 'metadata').
        :param int num: Number of files to store.
        :param int skip_obj_size: Size of obj in GB to skip (ex. 4 = 4GB)
        """
        info_msg = (
            f"HashStore Client - Begin retrieving and validating {obj_type} objects."
        )
        logging.info(info_msg)
        # Object and Metadata list
        metacat_obj_list = self.metacatdb.get_object_metadata_list(
            origin_dir, num, skip_obj_size
        )

        # Get list of objects to store from metacat db
        logging.info("HashStore Client - Refining object list for %s", obj_type)
        if obj_type == self.OBJ_TYPE:
            checked_obj_list = self.metacatdb.refine_list_for_objects(
                metacat_obj_list, "retrieve"
            )
        if obj_type == self.MET_TYPE:
            checked_obj_list = self.metacatdb.refine_list_for_metadata(
                metacat_obj_list, "retrieve"
            )

        start_time = datetime.now()

        # Set up pool and processes
        pool = multiprocessing.Pool()
        if obj_type == "object":
            pool.imap(self.validate_object, checked_obj_list)
        if obj_type == "metadata":
            pool.imap(self.validate_metadata, checked_obj_list)

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

        :param obj_tuple: Tuple containing pid_guid, obj_checksum_algo, obj_checksum.
        """
        pid_guid = obj_tuple[0]
        algo = obj_tuple[1]
        obj_db_checksum = obj_tuple[2]

        with self.hashstore.retrieve_object(pid_guid) as obj_stream:
            computed_digest = self.hashstore.get_hex_digest(obj_stream, algo)
            obj_stream.close()

        if computed_digest != obj_db_checksum:
            err_msg = (
                f"Assertion Error for pid/guid: {pid_guid} -"
                + f" Digest calculated from stream ({computed_digest}) does not match"
                + f" checksum from metacat db: {obj_db_checksum}"
            )
            logging.error(err_msg)
            print(err_msg)

        return

    def validate_metadata(self, obj_tuple):
        """Retrieves a metadata from HashStore and validates its checksum.

        :param obj_tuple: Tuple containing pid_guid, format_id, obj_checksum, obj_algorithm.
        """
        pid_guid = obj_tuple[0]
        namespace = obj_tuple[1]
        metadata_db_checksum = obj_tuple[2]
        algo = obj_tuple[3]

        with self.hashstore.retrieve_metadata(pid_guid, namespace) as metadata_stream:
            computed_digest = self.hashstore.computehash(metadata_stream, algo)
            metadata_stream.close()

        if computed_digest != metadata_db_checksum:
            err_msg = (
                f"Assertion Error for pid/guid: {pid_guid} -"
                + f" Digest calculated from stream ({computed_digest}) does not match"
                + f" checksum from metacat db: {metadata_db_checksum}"
            )
            logging.error(err_msg)
            print(err_msg)

        return

    def delete_objects_from_list(self, origin_dir, obj_type, num, skip_obj_size):
        """Deletes objects in a given directory into HashStore.

        :param str origin_dir: Directory to convert.
        :param str obj_type: Type of objects ('object' or 'metadata').
        :param int num: Number of files to store.
        :param int skip_obj_size: Size of obj in GB to skip (ex. 4 = 4GB)
        """
        info_msg = f"HashStore Client - Begin deleting {obj_type} objects."
        logging.info(info_msg)
        # Object and Metadata list
        metacat_obj_list = self.metacatdb.get_object_metadata_list(
            origin_dir, num, skip_obj_size
        )

        # Get list of objects to store from metacat db
        if obj_type == self.OBJ_TYPE:
            checked_obj_list = self.metacatdb.refine_list_for_objects(
                metacat_obj_list, "delete"
            )
        if obj_type == self.MET_TYPE:
            checked_obj_list = self.metacatdb.refine_list_for_metadata(
                metacat_obj_list, "delete"
            )

        start_time = datetime.now()

        # Setup pool and processes
        pool = multiprocessing.Pool()

        # Call 'obj_type' respective public API methods
        info_msg = f"HashStoreClient - Request to delete {len(checked_obj_list)} Objs"
        logging.info(info_msg)
        if obj_type == self.OBJ_TYPE:
            # results = pool.starmap(self.hashstore.store_object, checked_obj_list)
            pool.imap(self.try_delete_object, checked_obj_list)
        if obj_type == self.MET_TYPE:
            pool.imap(self.try_delete_metadata, checked_obj_list)

        # Close the pool and wait for all processes to complete
        pool.close()
        pool.join()

        end_time = datetime.now()
        content = (
            f"HashStoreClient (delete_objects_from_list):\n"
            f"Start Time: {start_time}\nEnd Time: {end_time}\n"
            + f"Total Time to Delete {len(checked_obj_list)} {obj_type}"
            + f" Objects: {end_time - start_time}\n"
        )
        logging.info(content)

    def try_delete_object(self, obj_pid):
        """Delete an object from HashStore and log exceptions as a warning.

        :param str obj_pid: PID of the object to delete.
        """
        try:
            self.hashstore.delete_object(obj_pid)
            return
        # pylint: disable=W0718
        except Exception as do_exception:
            print(do_exception)

    def try_delete_metadata(self, obj_tuple):
        """Delete an object from HashStore and log exceptions as a warning.

        :param obj_tuple: Tuple containing the PID and format ID (namespace).
        """
        pid_guid = obj_tuple[0]
        namespace = obj_tuple[1]
        try:
            self.hashstore.delete_metadata(pid_guid, namespace)
            return
        # pylint: disable=W0718
        except Exception as do_exception:
            print(do_exception)


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

    def get_object_metadata_list(self, origin_directory, num, skip_obj_size=None):
        """Query the Metacat database for the full object and metadata list, ordered by GUID.

        :param str origin_directory: 'var/metacat/data' or 'var/metacat/documents'.
        :param int num: Number of rows to retrieve from the Metacat database.
        :param int skip_obj_size: Size of obj in GB to skip (ex. 4 = 4GB), defaults to 'None'
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
                systemmetadata.checksum_algorithm, systemmetadata.size FROM identifier INNER JOIN systemmetadata
                ON identifier.guid = systemmetadata.guid ORDER BY identifier.guid{limit_query};"""
        cursor.execute(query)

        # Fetch all rows from the result set
        rows = cursor.fetchall()

        # Create full object list to store into HashStore
        print("Creating list of objects and metadata from metacat db")
        object_metadata_list = []
        gb_files_to_skip = skip_obj_size * (1024**3)
        for row in rows:
            size = row[6]
            if gb_files_to_skip is not None and size > gb_files_to_skip:
                pass
            else:
                # Get pid, filepath and formatId
                pid_guid = row[0]
                metadatapath_docid_rev = (
                    origin_directory + "/" + row[1] + "." + str(row[2])
                )
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

        :param List metacat_obj_list: List of tuple objects representing rows from Metacat database.
        :param str action: Action to perform. Options: "store", "retrieve", or "delete".
            - "store": Create a list of objects to store that do not exist in HashStore.
            - "retrieve": Create a list of objects that exist in HashStore.
            - "delete": Create a list of object PIDs to delete.

        :return: Refined list of tuple objects based on the specified action.
        :rtype: List
        """
        refined_object_list = []
        for tuple_item in metacat_obj_list:
            pid_guid = tuple_item[0]
            filepath_docid_rev = tuple_item[1]
            item_checksum = tuple_item[3]
            item_checksum_algorithm = tuple_item[4]
            if os.path.exists(filepath_docid_rev):
                if action == "store":
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
                    retrieve_object_tuple_item = (
                        pid_guid,
                        item_checksum_algorithm,
                        item_checksum,
                    )
                    refined_object_list.append(retrieve_object_tuple_item)
                if action == "delete":
                    refined_object_list.append(pid_guid)

        return refined_object_list

    def refine_list_for_metadata(self, metacat_obj_list, action):
        """Refine a list of metadata by checking for file existence and removing duplicates.

        :param List metacat_obj_list: List of tuple objects representing rows from metacat db.
        :param str action: Action to perform - "store", "retrieve", or "delete".
            - "store": Create a list of metadata to store that do not exist in HashStore.
            - "retrieve": Create a list of metadata that exist in HashStore.
            - "delete": Create a list of metadata pids with their format_ids.

        :return: List of tuple metadata based on the specified action.
        :rtype: List
        """
        refined_metadata_list = []
        for tuple_item in metacat_obj_list:
            pid_guid = tuple_item[0]
            filepath_docid_rev = tuple_item[1]
            metadata_namespace = tuple_item[2]
            item_checksum = tuple_item[3]
            item_checksum_algorithm = tuple_item[4]
            if os.path.exists(filepath_docid_rev):
                if action == "store":
                    tuple_item = (pid_guid, filepath_docid_rev, metadata_namespace)
                    refined_metadata_list.append(tuple_item)
                if action == "retrieve":
                    tuple_item = (
                        pid_guid,
                        metadata_namespace,
                        item_checksum,
                        item_checksum_algorithm,
                    )
                    refined_metadata_list.append(tuple_item)
                if action == "delete":
                    tuple_item = (
                        pid_guid,
                        metadata_namespace,
                    )
                    refined_metadata_list.append(tuple_item)
        return refined_metadata_list


def main():
    """Entry point of the HashStore client."""

    parser = HashStoreParser()
    args = parser.get_parser_args()

    # Client setup process
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
    # Can't use client app without first initializing HashStore
    store_path = getattr(args, "store_path")
    store_path_config_yaml = store_path + "/hashstore.yaml"
    if not os.path.exists(store_path_config_yaml):
        raise FileNotFoundError(
            f"Missing config file (hashstore.yaml) at store path: {store_path}."
            + " HashStore must first be initialized, use `--help` for more information."
        )
    # Setup logging, create log file if it doesn't already exist
    hashstore_py_log = store_path + "/python_client.log"
    python_log_file_path = Path(hashstore_py_log)
    if not os.path.exists(python_log_file_path):
        python_log_file_path.parent.mkdir(parents=True, exist_ok=True)
        open(python_log_file_path, "w", encoding="utf-8").close()
    # Check for logging level
    logging_level_arg = getattr(args, "logging_level")
    if logging_level_arg is None:
        logging_level = "INFO"
    else:
        logging_level = logging_level_arg
    logging.basicConfig(
        filename=python_log_file_path,
        level=logging_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Collect arguments to process
    pid = getattr(args, "object_pid")
    path = getattr(args, "object_path")
    algorithm = getattr(args, "object_algorithm")
    checksum = getattr(args, "object_checksum")
    checksum_algorithm = getattr(args, "object_checksum_algorithm")
    size = getattr(args, "object_size")
    formatid = getattr(args, "object_formatid")
    knbvm_test = getattr(args, "knbvm_flag")
    # Instantiate HashStore Client
    props = parser.load_store_properties(store_path_config_yaml)
    # Reminder: 'hashstore.yaml' only contains 4 of the required 5 properties
    props["store_path"] = store_path
    hashstore_c = HashStoreClient(props, knbvm_test)
    if knbvm_test:
        directory_to_convert = getattr(args, "source_directory")
        # Check if the directory to convert exists
        if os.path.exists(directory_to_convert):
            # If -nobj is supplied, limit the objects we work with
            number_of_objects_to_convert = getattr(args, "num_obj_to_convert")
            # Determine if we are working with objects or metadata
            directory_type = getattr(args, "source_directory_type")
            size_of_obj_to_skip = getattr(args, "gb_file_size_to_skip")
            accepted_directory_types = ["object", "metadata"]
            if directory_type not in accepted_directory_types:
                raise ValueError(
                    "Directory `-stype` cannot be empty, must be 'object' or 'metadata'."
                    + f" source_directory_type: {directory_type}"
                )
            if getattr(args, "store_to_hashstore"):
                hashstore_c.store_to_hashstore_from_list(
                    directory_to_convert,
                    directory_type,
                    number_of_objects_to_convert,
                    size_of_obj_to_skip,
                )
            if getattr(args, "retrieve_and_validate"):
                hashstore_c.retrieve_and_validate_from_hashstore(
                    directory_to_convert,
                    directory_type,
                    number_of_objects_to_convert,
                    size_of_obj_to_skip,
                )
            if getattr(args, "delete_from_hashstore"):
                hashstore_c.delete_objects_from_list(
                    directory_to_convert,
                    directory_type,
                    number_of_objects_to_convert,
                    size_of_obj_to_skip,
                )
        else:
            raise FileNotFoundError(
                f"Directory to convert is None or does not exist: {directory_to_convert}."
            )
    elif getattr(args, "client_getchecksum"):
        if pid is None:
            raise ValueError("'-pid' option is required")
        if algorithm is None:
            raise ValueError("'-algo' option is required")
        # Calculate the hex digest of a given pid with algorithm supplied
        digest = hashstore_c.hashstore.get_hex_digest(pid, algorithm)
        print(f"guid/pid: {pid}")
        print(f"algorithm: {algorithm}")
        print(f"Checksum/Hex Digest: {digest}")

    elif getattr(args, "client_storeobject"):
        if pid is None:
            raise ValueError("'-pid' option is required")
        if path is None:
            raise ValueError("'-path' option is required")
        # Store object to HashStore
        object_metadata = hashstore_c.hashstore.store_object(
            pid, path, algorithm, checksum, checksum_algorithm, size
        )
        print(f"Object Metadata:\n{object_metadata}")

    elif getattr(args, "client_storemetadata"):
        if pid is None:
            raise ValueError("'-pid' option is required")
        if path is None:
            raise ValueError("'-path' option is required")
        # Store metadata to HashStore
        metadata_cid = hashstore_c.hashstore.store_metadata(pid, path, formatid)
        print(f"Metadata ID: {metadata_cid}")

    elif getattr(args, "client_retrieveobject"):
        if pid is None:
            raise ValueError("'-pid' option is required")
        # Retrieve object from HashStore and display the first 1000 bytes
        object_stream = hashstore_c.hashstore.retrieve_object(pid)
        object_content = object_stream.read(1000).decode("utf-8")
        object_stream.close()
        print(object_content)
        print("...\n<-- Truncated for Display Purposes -->")

    elif getattr(args, "client_retrievemetadata"):
        if pid is None:
            raise ValueError("'-pid' option is required")
        # Retrieve metadata from HashStore and display the first 1000 bytes
        metadata_stream = hashstore_c.hashstore.retrieve_metadata(pid, formatid)
        metadata_content = metadata_stream.read(1000).decode("utf-8")
        metadata_stream.close()
        print(metadata_content)
        print("...\n<-- Truncated for Display Purposes -->")

    elif getattr(args, "client_deleteobject"):
        if pid is None:
            raise ValueError("'-pid' option is required")
        # Delete object from HashStore
        delete_status = hashstore_c.hashstore.delete_object(pid)
        print(f"Object Deleted (T/F): {delete_status}")

    elif getattr(args, "client_deletemetadata"):
        if pid is None:
            raise ValueError("'-pid' option is required")
        # Delete metadata from HashStore
        delete_status = hashstore_c.hashstore.delete_metadata(pid, formatid)
        print(
            f"Metadata for pid: {pid} & formatid: {formatid}\nDeleted (T/F): {delete_status}"
        )


if __name__ == "__main__":
    main()
