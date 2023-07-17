"""HashStore Command Line App"""
import os
import yaml
from argparse import ArgumentParser
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


def convert_directory_to_hashstore(config_yaml):
    """Store objects in a given directory into HashStore with a random pid."""
    properties = load_properties(config_yaml)
    store = get_hashstore(properties)

    # Get list of files from directory
    obj_list = os.listdir(directory_to_convert)

    # Store them into HashStore
    # pylint: disable=C0103
    pid_count = 1
    for obj in obj_list:
        # Temporary unique identifier
        pid = f"dou.test.{pid_count}"
        pid_count += 1
        obj_file_path = directory_to_convert + "/" + obj
        _hash_address = store.store_object(pid, obj_file_path)


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
            store_path = getattr(args, "store_path")
            store_path_config_yaml = store_path + "/hashstore.yaml"
            if os.path.exists(store_path_config_yaml):
                convert_directory_to_hashstore(store_path_config_yaml)
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
