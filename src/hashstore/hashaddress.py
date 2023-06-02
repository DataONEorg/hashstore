"""HashAddress must be returned for all HashStore implementations"""
from collections import namedtuple


class HashAddress(
    namedtuple(
        "HashAddress", ["id", "relpath", "abspath", "is_duplicate", "hex_digests"]
    )
):
    """File address containing file's path on disk and its content hash ID.

    Args:
        ab_id (str): Hash ID (hexdigest) of file contents.
        relpath (str): Relative path location to :attr:`HashFS.root`.
        abspath (str): Absolute path location of file on disk.
        is_duplicate (boolean, optional): Whether the hash address created was
            a duplicate of a previously existing file. Can only be ``True``
            after a put operation. Defaults to ``False``.
        hex_digests (dict, optional): A list of hex digests to validate objects
            (md5, sha1, sha256, sha384, sha512)
    """

    # Default value to prevent dangerous default value
    def __new__(cls, ab_id, relpath, abspath, is_duplicate=False, hex_digests=None):
        return super(HashAddress, cls).__new__(
            cls, ab_id, relpath, abspath, is_duplicate, hex_digests
        )
