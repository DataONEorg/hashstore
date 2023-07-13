"""Hashstore Interface"""
from abc import ABC, abstractmethod
from collections import namedtuple
import importlib.metadata


class HashStore(ABC):
    """HashStore is a content-addressable file management system that
    utilizes a persistent identifier (PID) in the form of a hex digest
    value to address files."""

    @staticmethod
    def version():
        """Return the version number"""
        __version__ = importlib.metadata.version("hashstore")
        return __version__

    @abstractmethod
    def store_object(
        self,
        pid,
        data,
        additional_algorithm,
        checksum,
        checksum_algorithm,
    ):
        """The `store_object` method is responsible for the atomic storage of objects to
        disk using a given InputStream and a persistent identifier (pid). Upon
        successful storage, the method returns a HashAddress object containing
        relevant file information, such as the file's cid, relative path, absolute
        path, duplicate object status, and hex digest map of algorithms and
        checksums. `store_object` also ensures that an object is stored only once by
        synchronizing multiple calls and rejecting calls to store duplicate objects.

        The file's id is determined by calculating the SHA-256 hex digest of the
        provided pid, which is also used as the permanent address of the file. The
        file's identifier is then sharded using a depth of 3 and width of 2,
        delimited by '/' and concatenated to produce the final permanent address
        and is stored in the `/store_directory/objects/` directory.

        By default, the hex digest map includes the following hash algorithms:
        Default algorithms and hex digests to return: md5, sha1, sha256, sha384, sha512,
        which are the most commonly used algorithms in dataset submissions to DataONE
        and the Arctic Data Center. If an additional algorithm is provided, the
        `store_object` method checks if it is supported and adds it to the map along
        with its corresponding hex digest. An algorithm is considered "supported" if it
        is recognized as a valid hash algorithm in the `hashlib` library.

        Similarly, if a checksum and a checksumAlgorithm value are provided,
        `store_object` validates the object to ensure it matches what is provided
        before moving the file to its permanent address.

        Args:
            pid (string): Authority-based identifier.
            data (mixed): String or path to object.
            additional_algorithm (string): Additional hex digest to include.
            checksum (string): Checksum to validate against.
            checksum_algorithm (string): Algorithm of supplied checksum.

        Returns:
            address (HashAddress): Object that contains the permanent address, relative
            file path, absolute file path, duplicate file boolean and hex digest dictionary.
        """
        raise NotImplementedError()

    @abstractmethod
    def store_metadata(self, pid, metadata, format_id):
        """The `store_metadata` method is responsible for adding and/or updating metadata
        (ex. `sysmeta`) to disk using a given path/stream, a persistent identifier `pid`
        and a metadata `format_id`. The metadata object's permanent address, which is
        determined by calculating the SHA-256 hex digest of the provided `pid` + `format_id`.

        Upon successful storage of metadata, `store_metadata` returns a string that
        represents the file's permanent address. Lastly, the metadata objects are stored
        in parallel to objects in the `/store_directory/metadata/` directory.

        Args:
            pid (string): Authority-based identifier.
            format_id (string): Metadata format
            metadata (mixed): String or path to metadata document.

        Returns:
            metadata_cid (string): Address of the metadata document.
        """
        raise NotImplementedError()

    @abstractmethod
    def retrieve_object(self, pid):
        """The `retrieve_object` method retrieves an object from disk using a given
        persistent identifier (pid). If the object exists (determined by calculating
        the object's permanent address using the SHA-256 hash of the given pid), the
        method will open and return a buffered object stream ready to read from.

        Args:
            pid (string): Authority-based identifier.

        Returns:
            obj_stream (io.BufferedReader): A buffered stream of a data object.
        """
        raise NotImplementedError()

    @abstractmethod
    def retrieve_metadata(self, pid, format_id):
        """The 'retrieve_metadata' method retrieves the metadata object from disk using
        a given persistent identifier (pid) and metadata namespace (format_id).
        If the object exists (determined by calculating the metadata object's permanent
        address using the SHA-256 hash of the given pid+format_id), the method will open
        and return a buffered metadata stream ready to read from.

        Args:
            pid (string): Authority-based identifier
            format_id (string): Metadata format

        Returns:
            metadata_stream (io.BufferedReader): A buffered stream of a metadata object.
        """
        raise NotImplementedError()

    @abstractmethod
    def delete_object(self, pid):
        """The 'delete_object' method deletes an object permanently from disk using a
        given persistent identifier.

        Args:
            pid (string): Authority-based identifier.

        Returns:
            boolean: `True` upon successful deletion.
        """
        raise NotImplementedError()

    @abstractmethod
    def delete_metadata(self, pid, format_id):
        """The 'delete_metadata' method deletes a metadata document permanently
        from disk using a given persistent identifier and format_id.

        Args:
            pid (string): Authority-based identifier
            format_id (string): Metadata format

        Returns:
            boolean: `True` upon successful deletion.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_hex_digest(self, pid, algorithm):
        """The 'get_hex_digest' method calculates the hex digest of an object that exists
        in HashStore using a given persistent identifier and hash algorithm.

        Args:
            pid (string): Authority-based identifier.
            algorithm (string): Algorithm of hex digest to generate.

        Returns:
            hex_digest (string): Hex digest of the object.
        """
        raise NotImplementedError()


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
