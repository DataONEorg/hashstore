"""Default configuration variables for HashStore"""
DIR_DEPTH = 3
DIR_WIDTH = 2
SYSMETA_NS = "http://ns.dataone.org/service/types/v2.0"
# Algorithm values supported by python hashlib 3.9.0+
DEFAULT_ALGO_LIST = ["sha1", "sha256", "sha384", "sha512", "md5"]
OTHER_ALGO_LIST = ["sha224", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s"]
