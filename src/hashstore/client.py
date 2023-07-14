"""HashStore Command Line App"""
from argparse import ArgumentParser
from hashstore import HashStoreFactory


def add_client_optional_arguments(argp):
    """Adds the optional arguments for HashStore Client.

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
        "-dir",
        dest="directory_to_convert",
        help="Directory of objects to convert to a HashStore",
    )


def get_hashstore(properties):
    """Create a HashStore instance with the supplied properties.

    Args:
        properties: HashStore properties (see 'FileHashStore' module for details)

    Returns:
        hashstore (FileHashStore): HashStore
    """
    store = HashStoreFactory()

    # Get HashStore from factory
    module_name = "filehashstore"
    class_name = "FileHashStore"

    # Class variables
    hashstore = store.get_hashstore(module_name, class_name, properties)
    return hashstore


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
    if getattr(args, "create_hashstore"):
        # Create a HashStore at the given directory
        # Get store attributes and validate properties
        props = {
            "store_path": getattr(args, "store_path"),
            "store_depth": getattr(args, "depth"),
            "store_width": getattr(args, "width"),
            "store_algorithm": getattr(args, "algorithm"),
            "store_metadata_namespace": getattr(args, "formatid"),
        }
        my_store = get_hashstore(props)
