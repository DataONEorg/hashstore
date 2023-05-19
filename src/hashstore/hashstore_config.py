"""Default configuration variables for HashStore"""
# Default path for `FileHashStore` if no path is provided
STORE_PATH = "/var/filehashstore/"
# Desired amount of directories when sharding an object to form the permanent address
DIR_DEPTH = 3 # DO NOT CHANGE UNLESS SETTING UP NEW HASHSTORE
# Width of directories created when sharding an object to form the permanent address
DIR_WIDTH = 2 # DO NOT CHANGE UNLESS SETTING UP NEW HASHSTORE
SYSMETA_NS = "http://ns.dataone.org/service/types/v2.0"
# Algorithm values supported by python hashlib 3.9.0+
DEFAULT_ALGO_LIST = ["sha1", "sha256", "sha384", "sha512", "md5"]
OTHER_ALGO_LIST = ["sha224", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s"]
