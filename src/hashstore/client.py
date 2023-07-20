"""HashStore Command Line App"""
import os
from argparse import ArgumentParser
from datetime import datetime
import queue
import threading
import yaml
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
    factory = HashStoreFactory()

    # Get HashStore from factory
    module_name = "filehashstore"
    class_name = "FileHashStore"

    # Class variables
    hashstore = factory.get_hashstore(module_name, class_name, properties)
    return hashstore


def load_properties(hashstore_yaml):
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
            "HashStore CLI Client - load_properties: hashstore.yaml not found"
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


def write_text_to_path(directory, filename, content):
    """Write a text file to a given directory."""
    # Combine the directory path and filename
    file_path = f"{directory}/{filename}"

    # Open the file in write mode ('w')
    with open(file_path, "w", encoding="utf-8") as file:
        # Write the content to the file
        file.write(content)


def convert_directory_to_hashstore(obj_directory, config_yaml, num):
    """Store objects in a given directory into HashStore with a random pid.

    Args:
        obj_directory (str): Directory to convert
        config_yaml (str): Path to HashStore config file `hashstore.yaml`
        num (int): Number of files to store
    """

    properties = load_properties(config_yaml)
    store = get_hashstore(properties)

    def process_store_obj_queue(my_queue):
        """Store object to HashStore"""
        while not my_queue.empty():
            queue_item = my_queue.get()
            pid = queue_item["pid"]
            obj_path = queue_item["obj_path"]
            _hash_address = store.store_object(pid, obj_path)

    # Get list of files from directory
    obj_list = os.listdir(obj_directory)
    # Create queue
    store_obj_queue = queue.Queue(maxsize=len(obj_list))

    # Check number of files to store
    if num is None:
        checked_num = len(obj_list)
    else:
        checked_num = int(num)

    # Make a queue of objects to store
    for i in range(0, checked_num):
        item_dict = {
            "pid": f"dou.test.{i}",
            "obj_path": obj_directory + "/" + obj_list[i],
        }
        store_obj_queue.put(item_dict)

    # Number of threads
    num_threads = 5

    # Create and start threads
    start_time = datetime.now()
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(
            target=process_store_obj_queue, args=(store_obj_queue,)
        )
        thread.start()
        threads.append(thread)

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    end_time = datetime.now()
    content = f"Start Time: {start_time}\nEnd Time: {end_time}"
    write_text_to_path(properties["store_path"], "client_metadata.txt", content)


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

    # Convert a directory into HashStore if config file and directory exist
    elif getattr(args, "convert_directory") is not None:
        directory_to_convert = getattr(args, "convert_directory")
        if os.path.exists(directory_to_convert):
            number_of_objects_to_convert = getattr(args, "num_obj_to_convert")
            store_path = getattr(args, "store_path")
            store_path_config_yaml = store_path + "/hashstore.yaml"
            if os.path.exists(store_path_config_yaml):
                convert_directory_to_hashstore(
                    directory_to_convert,
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
