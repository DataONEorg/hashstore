"""HashStore Command Line App"""
import sys
import logging
import os
from argparse import ArgumentParser
from datetime import datetime
import hashlib
import multiprocessing
import yaml
import pg8000
from hashstore import HashStoreFactory


def add_client_optional_arguments(argp):
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


def get_hashstore(properties):
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


def load_store_properties(hashstore_yaml):
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
            "HashStore CLI Client - load_store_properties: hashstore.yaml not found"
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


def load_db_properties(pgdb_yaml):
    """Get and return the contents of a postgres config file

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
            "HashStore CLI Client - load_db_properties: pgdb.yaml not found"
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


def write_text_to_path(directory, filename, content):
    """Write a text file to a given directory."""
    # Combine the directory path and filename
    file_path = f"{directory}/{filename}.txt"

    # Open the file in write mode ('w')
    with open(file_path, "w", encoding="utf-8") as file:
        # Write the content to the file
        file.write(content)


def get_sha256_hex_digest(string):
    """Calculate the SHA-256 digest of a UTF-8 encoded string.

    Args:
        string (string): String to convert.

    Returns:
        hex (string): Hexadecimal string.
    """
    hex_digest = hashlib.sha256(string.encode("utf-8")).hexdigest()
    return hex_digest


def get_objs_from_metacat_db(properties, obj_directory, num, store):
    """Get the list of objects from knbvm's metacat db to store into HashStore"""
    # Note: Manually create `pgdb.yaml` for security purposes
    pgyaml_path = properties["store_path"] + "/pgdb.yaml"
    print(f"Retrieving db config from: {pgyaml_path}")

    db_properties = load_db_properties(pgyaml_path)
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

    # Query to get rows from `identifier` table
    query = f"SELECT * FROM identifier LIMIT {num};"
    cursor.execute(query)

    # Fetch all rows from the result set
    rows = cursor.fetchall()

    # Create object list to store into HashStore
    print("Creating list of objects to store into HashStore")
    checked_obj_list = []
    for row in rows:
        # Get pid and filename
        pid_guid = row[0]
        filepath_docid_rev = obj_directory + "/" + row[1] + "." + str(row[2])
        tuple_item = (pid_guid, filepath_docid_rev)
        # Only add to the list if it is an object, not metadata document
        if os.path.exists(filepath_docid_rev):
            # If the file has already been stored, skip it
            if store.exists("objects", store.get_sha256_hex_digest(pid_guid)):
                print(f"Object exists in HashStore for guid: {pid_guid}")
            else:
                checked_obj_list.append(tuple_item)

    # Close the cursor and connection when done
    cursor.close()
    conn.close()

    return checked_obj_list


def get_metadata_from_metacat_db(properties, metadata_directory, num):
    """Get the list of metadata objs from knbvm's metacat db to store into HashStore"""
    # Note: Manually create `pgdb.yaml` for security purposes
    pgyaml_path = properties["store_path"] + "/pgdb.yaml"
    print(f"Retrieving db config from: {pgyaml_path}")

    db_properties = load_db_properties(pgyaml_path)
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
    query = """SELECT identifier.guid, identifier.docid, identifier.rev,
            systemmetadata.object_format FROM identifier INNER JOIN systemmetadata
            ON identifier.guid = systemmetadata.guid;"""
    cursor.execute(query)

    # Fetch all rows from the result set
    rows = cursor.fetchall()

    # Create metadata list to store into HashStore
    print("Creating list of metadata to store into HashStore")
    checked_metadata_list = []
    for row in rows:
        # Get pid, filepath and formatId
        pid_guid = row[0]
        metadatapath_docid_rev = metadata_directory + "/" + row[1] + "." + str(row[2])
        metadata_namespace = row[3]
        tuple_item = (pid_guid, metadatapath_docid_rev, metadata_namespace)
        # Only add to the list if it is an object, not metadata document
        if os.path.exists(metadatapath_docid_rev):
            # If the file already exists, don't attempt to add it
            print(f"Metadata doc found: {metadatapath_docid_rev} for pid: {pid_guid}")
            checked_metadata_list.append(tuple_item)

    # Close the cursor and connection when done
    cursor.close()
    conn.close()

    return checked_metadata_list


def store_to_hashstore(origin_dir, obj_type, config_yaml, num):
    """Store objects in a given directory into HashStore

    Args:
        origin_dir (str): Directory to convert
        obj_type (str): 'object' or 'metadata'
        config_yaml (str): Path to HashStore config file `hashstore.yaml`
        num (int): Number of files to store
    """
    properties = load_store_properties(config_yaml)
    store = get_hashstore(properties)

    # Get list of files from directory
    file_list = os.listdir(origin_dir)
    checked_num_of_files = len(file_list)
    # Check number of files to store
    if num is not None:
        checked_num_of_files = int(num)

    # Get list of objects to store from metacat db
    if obj_type == "object":
        checked_obj_list = get_objs_from_metacat_db(
            properties, origin_dir, checked_num_of_files, store
        )
    if obj_type == "metadata":
        checked_obj_list = get_metadata_from_metacat_db(
            properties, origin_dir, checked_num_of_files
        )

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
            logging.info(result)

    # Close the pool and wait for all processes to complete
    pool.close()
    pool.join()

    end_time = datetime.now()
    content = (
        f"Start Time: {start_time}\nEnd Time: {end_time}\n"
        + f"Total Time to Store {len(checked_obj_list)} {obj_type}"
        + f" Objects: {end_time - start_time}\n"
    )
    logging.info(content)


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
    add_client_optional_arguments(parser)

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

    # Create HashStore if -chs flag is true
    if getattr(args, "create_hashstore"):
        # Create a HashStore at the given directory
        # Get store attributes, HashStore will validate properties
        props = {
            "store_path": getattr(args, "store_path"),
            "store_depth": int(getattr(args, "depth")),
            "store_width": int(getattr(args, "width")),
            "store_algorithm": getattr(args, "algorithm"),
            "store_metadata_namespace": getattr(args, "formatid"),
        }
        get_hashstore(props)

    # Convert a directory to a HashStore if config file present
    elif getattr(args, "convert_directory") is not None:
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
                store_to_hashstore(
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
