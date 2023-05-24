"""Default configuration variables for HashStore"""

############### Store Path ###############
# Default path for `FileHashStore` if no path is provided
STORE_PATH = "/var/filehashstore/"

############### Directory Structure ###############
# Desired amount of directories when sharding an object to form the permanent address
DIR_DEPTH = 3  # WARNING: DO NOT CHANGE UNLESS SETTING UP NEW HASHSTORE
# Width of directories created when sharding an object to form the permanent address
DIR_WIDTH = 2  # WARNING: DO NOT CHANGE UNLESS SETTING UP NEW HASHSTORE
# Example:
# Below, objects are shown listed in directories that are 3 levels deep (DIR_DEPTH=3),
# with each directory consisting of 2 characters (DIR_DEPTH=2).
#    /var/filehashstore/objects
#    ├── 7f
#    │   └── 5c
#    │       └── c1
#    │           └── 8f0b04e812a3b4c8f686ce34e6fec558804bf61e54b176742a7f6368d6

############### Format of the Metadata ###############
SYSMETA_NS = "http://ns.dataone.org/service/types/v2.0"


############### Hash Algorithms ###############
# Hash algorithm to use when calculating object's hex digest for the permanent address
ALGORITHM = "sha256"
# Algorithm values supported by python hashlib 3.9.0+
# The default algorithm list includes the hash algorithms calculated when storing an
# object to disk and returned to the caller after successful storage.
DEFAULT_ALGO_LIST = ["sha1", "sha256", "sha384", "sha512", "md5"]
# The other algorithm list consists of additional algorithms that can be included for
# calculating when storing objects, in addition to the default list.
OTHER_ALGO_LIST = [
    "sha224",
    "sha3_224",
    "sha3_256",
    "sha3_384",
    "sha3_512",
    "blake2b",
    "blake2s",
]
