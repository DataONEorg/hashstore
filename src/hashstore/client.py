"""HashStore Command Line App"""
from argparse import ArgumentParser

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

    ### Positional Arguments

    # Path of the HashStore
    parser.add_argument("store_path", help="Path of the HashStore")

    ### Optional Arguments

    # HashStore creation and property arguments
    parser.add_argument("-chs", dest="action", help="Create a HashStore")
    parser.add_argument("-store_depth", dest="depth", help="Depth of HashStore")
    parser.add_argument("-store_width", dest="width", help="Width of HashStore")
    parser.add_argument(
        "-store_algorithm",
        dest="algorithm",
        help="Algorithm to use when calculating object address",
    )
    parser.add_argument(
        "-store_namespace",
        dest="formatid",
        help="Default metadata namespace for metadata",
    )

    # Directory to convert into a HashStore
    parser.add_argument(
        "-dir",
        dest="action",
        help="Directory of objects to convert to a HashStore",
    )

    # Public API Equivalent Methods
    # object identifier
    parser.add_argument("-pid", dest="pid", help="Object Identifier")
    # store_object
    parser.add_argument("-sobj", dest="action", help="Store an object to the HashStore")
    # delete_object
    parser.add_argument(
        "-dobj", dest="action", help="Delete an object to the HashStore"
    )

    # TODO: Add methods and functionality
    parser.parse_args(["--help"])

    # args = parser.parse_args()
    # print(args)
