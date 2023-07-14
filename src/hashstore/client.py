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

    # Positional Arguments
    # Path of the HashStore to create and/or store/delete objects to/from
    parser.add_argument("store_path", help="Path of the HashStore")

    # Optional Arguments
    parser.add_argument("-chs", dest="action", help="Create a HashStore")
    parser.add_argument("-sobj", dest="action", help="Store an object to the HashStore")
    parser.add_argument(
        "-dobj", dest="action", help="Delete an object to the HashStore"
    )
    parser.add_argument("-pid", dest="pid", help="Object Identifier")

    parser.parse_args(["--help"])
