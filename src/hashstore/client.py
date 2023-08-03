"""HashStore Command Line App"""
import logging
import os
from argparse import ArgumentParser
from datetime import datetime
import multiprocessing
import yaml
import pg8000
from hashstore import HashStoreFactory


# Supporting Methods


class HashStoreClient:
    """Create a HashStore"""

    def __init__(self, properties):
        logging.info("Initializing HashStore")
        factory = HashStoreFactory()

        # Get HashStore from factory
        module_name = "filehashstore"
        class_name = "FileHashStore"

        # Class variables
        self.hashstore = factory.get_hashstore(module_name, class_name, properties)

    def retrieve_and_validate(self, obj_tuple):
        """Retrieve and validate a list of objects."""
        pid_guid = obj_tuple[0]
        algo = obj_tuple[4]
        checksum = obj_tuple[3]
        obj_stream = self.hashstore.retrieve_object(pid_guid)
        digest = self.hashstore.computehash(obj_stream, algo)
        obj_stream.close()
        # Check algorithm
        if digest != checksum:
            err_msg = (
                f"Unexpected Exception for pid/guid: {pid_guid} -"
                + f" Digest calcualted from stream ({digest}) does not match"
                + f" checksum from metacata db: {checksum}"
            )
            raise AssertionError(err_msg)
        else:
            info_msg = (
                f"Checksums match for pid/guid: {pid_guid} -"
                + f" Digest calcualted from stream: {digest}."
                + f" Checksum from metacata db: {checksum}."
            )
            logging.info(info_msg)


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


def _get_hashstore(properties):
    """Create a HashStore instance with the supplied properties.

    Args:
        properties: HashStore properties (see 'FileHashStore' module for details)

    Returns:
        hashstore (FileHashStore): HashStore
    """
    logging.info("Initializing HashStore")
    factory = HashStoreFactory()

    # Get HashStore from factory
    module_name = "filehashstore"
    class_name = "FileHashStore"

    # Class variables
    hashstore = factory.get_hashstore(module_name, class_name, properties)
    return hashstore


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


def _load_metacat_db_properties(pgdb_yaml):
    """Get and return the contents of a config file with credentials
    to access a postgres db.

    Args:
        pgdb_yaml (string): Path to yaml file

    Returns:
        hashstore_yaml_dict (dict): postgres db config properties
    """
    db_keys = [
        "db_user",
        "db_password",
        "db_host",
        "db_port",
        "db_name",
    ]

    if not os.path.exists(pgdb_yaml):
        exception_string = (
            "HashStore CLI Client - _load_metacat_db_properties: pgdb.yaml not found"
            + " in store root path."
        )
        raise FileNotFoundError(exception_string)
    # Open file
    with open(pgdb_yaml, "r", encoding="utf-8") as file:
        yaml_data = yaml.safe_load(file)

    # Get database values
    db_yaml_dict = {}
    for key in db_keys:
        checked_property = yaml_data[key]
        db_yaml_dict[key] = checked_property
    return db_yaml_dict


def _get_full_obj_list_from_metacat_db(properties, metacat_dir, num):
    """Get the list of objects and metadata from knbvm's metacat db"""
    # Note: Manually create `pgdb.yaml` for security purposes
    pgyaml_path = properties["store_path"] + "/pgdb.yaml"
    print(f"Retrieving db config from: {pgyaml_path}")

    db_properties = _load_metacat_db_properties(pgyaml_path)
    db_user = db_properties["db_user"]
    db_password = db_properties["db_password"]
    db_host = db_properties["db_host"]
    db_port = db_properties["db_port"]
    db_name = db_properties["db_name"]

    # Create a connection to the database
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
        metadatapath_docid_rev = metacat_dir + "/" + row[1] + "." + str(row[2])
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


def _refine_object_list(store, metacat_obj_list, action):
    """Refine a list of objects by checking for file existence and removing duplicates."""
    refined_list = []
    for tuple_item in metacat_obj_list:
        pid_guid = tuple_item[0]
        filepath_docid_rev = tuple_item[1]
        if os.path.exists(filepath_docid_rev):
            if action == "store":
                # If the file has already been stored, skip it
                if store.exists("objects", store.get_sha256_hex_digest(pid_guid)):
                    print(
                        f"Refining Object List: Skipping {pid_guid} - object exists in HashStore"
                    )
                else:
                    refined_list.append(tuple_item)
            if action == "retrieve":
                if store.exists("objects", store.get_sha256_hex_digest(pid_guid)):
                    refined_list.append(tuple_item)

    return refined_list


def _refine_metadata_list(store, metacat_obj_list):
    """Refine a list of metadata by checking for file existence and removing duplicates."""
    refined_list = []
    for obj in metacat_obj_list:
        pid_guid = obj[0]
        filepath_docid_rev = obj[1]
        metadata_namespace = obj[2]
        if os.path.exists(filepath_docid_rev):
            # If the file has already been stored, skip it
            if store.exists("metadata", store.get_sha256_hex_digest(pid_guid)):
                print(
                    f"Skipping store_metadata for {pid_guid} - metadata exists in HashStore"
                )
            else:
                tuple_item = (pid_guid, metadata_namespace, filepath_docid_rev)
                refined_list.append(tuple_item)
    return refined_list


# Concrete Methods


def store_to_hashstore_from_list(origin_dir, obj_type, config_yaml, num):
    """Store objects in a given directory into HashStore

    Args:
        origin_dir (str): Directory to convert
        obj_type (str): 'object' or 'metadata'
        config_yaml (str): Path to HashStore config file `hashstore.yaml`
        num (int): Number of files to store
    """
    properties = _load_store_properties(config_yaml)
    store = _get_hashstore(properties)

    # Get list of files from directory
    file_list = os.listdir(origin_dir)
    checked_num_of_files = len(file_list)
    # Check number of files to store
    if num is not None:
        checked_num_of_files = int(num)

    # Object and Metadata list
    metacat_obj_list = _get_full_obj_list_from_metacat_db(
        properties, origin_dir, checked_num_of_files
    )

    # Get list of objects to store from metacat db
    if obj_type == "object":
        checked_obj_list = _refine_object_list(store, metacat_obj_list, "store")
    if obj_type == "metadata":
        checked_obj_list = _refine_metadata_list(store, metacat_obj_list)

    start_time = datetime.now()

    # Setup pool and processes
    # num_processes = os.cpu_count() - 2
    # pool = multiprocessing.Pool(processes=num_processes)
    pool = multiprocessing.Pool()

    # Call 'obj_type' respective public API methods
    if obj_type == "object":
        logging.info("Storing objects")
        results = pool.starmap(store.store_object, checked_obj_list)
    if obj_type == "metadata":
        logging.info("Storing metadata")
        results = pool.starmap(store.store_metadata, checked_obj_list)

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
        f"store_to_hashstore_from_list:\n"
        f"Start Time: {start_time}\nEnd Time: {end_time}\n"
        + f"Total Time to Store {len(checked_obj_list)} {obj_type}"
        + f" Objects: {end_time - start_time}\n"
    )
    logging.info(content)


def retrieve_and_validate_from_hashstore(origin_dir, obj_type, config_yaml, num):
    "Retrieve objects or metadata from a Hashstore and validate the content."
    properties = _load_store_properties(config_yaml)
    # store = _get_hashstore(properties)
    store = HashStoreClient(properties)

    checked_num_of_files = None
    # Check number of files to store
    if num is not None:
        checked_num_of_files = int(num)

    # Object and Metadata list
    metacat_obj_list = _get_full_obj_list_from_metacat_db(
        properties, origin_dir, checked_num_of_files
    )

    # Get list of objects to store from metacat db
    if obj_type == "object":
        checked_obj_list = _refine_object_list(
            store.hashstore, metacat_obj_list, "retrieve"
        )
    if obj_type == "metadata":
        checked_obj_list = _refine_metadata_list(store.hashstore, metacat_obj_list)

    start_time = datetime.now()

    # Setup pool and processes
    pool = multiprocessing.Pool()

    if obj_type == "object":
        logging.info("Retrieving objects")
        results = pool.map(store.retrieve_and_validate, checked_obj_list)
    if obj_type == "metadata":
        logging.info("Retrieiving metadata")
        # TODO

    # Log exceptions
    cleanup_msg = "Checking results and logging exceptions"
    print(cleanup_msg)
    logging.info(cleanup_msg)
    for result in results:
        if isinstance(result, Exception):
            print(result)
            logging.info(result)

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


def get_obj_hex_digest_from_store(config_yaml, pid_guid, obj_algo):
    """Given a pid and algorithm, get the hex digest of the object"""
    properties = _load_store_properties(config_yaml)
    store = _get_hashstore(properties)

    digest = store.get_hex_digest(pid, algorithm)
    print(f"guid/pid: {pid_guid}")
    print(f"algorithm: {obj_algo}")
    print(f"digest: {digest}")


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
        level=logging.DEBUG,
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
        _get_hashstore(props)

    elif getattr(args, "convert_directory") is not None:
        # Perform operations to a HashStore if config file present
        directory_to_convert = getattr(args, "convert_directory")
        if os.path.exists(directory_to_convert):
            number_of_objects_to_convert = getattr(args, "num_obj_to_convert")
            store_path = getattr(args, "store_path")
            store_path_config_yaml = store_path + "/hashstore.yaml"
            directory_type = getattr(args, "convert_directory_type")
            accepted_directory_types = ["object", "metadata"]
            if directory_type not in accepted_directory_types:
                raise ValueError(
                    "Directory `-cvt` cannot be empty, must be 'object' or 'metadata'."
                    + f" convert_directory_type: {directory_type}"
                )
            if os.path.exists(store_path_config_yaml):
                if getattr(args, "retrieve_and_validate"):
                    retrieve_and_validate_from_hashstore(
                        directory_to_convert,
                        directory_type,
                        store_path_config_yaml,
                        number_of_objects_to_convert,
                    )
                else:
                    store_to_hashstore_from_list(
                        directory_to_convert,
                        directory_type,
                        store_path_config_yaml,
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
        store_path = getattr(args, "store_path")
        store_path_config_yaml = store_path + "/hashstore.yaml"

        if os.path.exists(store_path_config_yaml):
            get_obj_hex_digest_from_store(store_path_config_yaml, pid, algorithm)
        else:
            # If HashStore does not exist, raise exception
            # Calling app must create HashStore first before calling methods
            raise FileNotFoundError(
                f"Missing config file (hashstore.yaml) at store path: {store_path}."
                + " HashStore must be initialized, use `--help` for more information."
            )
