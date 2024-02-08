"""Hashstore Interface"""
from abc import ABC, abstractmethod
from collections import namedtuple
import importlib.metadata
import importlib.util


class HashStore(ABC):
    """HashStore is a content-addressable file management system that utilizes
    an object's content identifier (hex digest/checksum) to address files."""

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
        expected_object_size,
    ):
        """Atomic storage of objects to disk using a given stream. The `store_object` method
        ensures atomic storage of objects to disk. Upon successful storage, it returns an
        `ObjectMetadata` object containing relevant file information, such as the file's id
        (used to locate the object on disk), the file's size, and a hex digest dictionary of
        algorithms and checksums. The method also tags the object, creating references for
        discoverability.

        `store_object` ensures that an object is stored only once by synchronizing multiple calls
        and rejecting attempts to store duplicate objects. If called without a pid, it stores the
        object without tagging, and it becomes the caller's responsibility to finalize the process
        by calling `tag_object` after verifying the correct object is stored.

        The file's id is determined by calculating the object's content identifier based on the
        store's default algorithm, which is also the permanent address of the file. The file's
        identifier is then sharded using the store's configured depth and width, delimited by '/',
        and concatenated to produce the final permanent address. This address is stored in the
        `/store_directory/objects/` directory.

        By default, the hex digest map includes common hash algorithms (md5, sha1, sha256, sha384,
        sha512). If an additional algorithm is provided, the method checks if it is supported and
        adds it to the hex digests dictionary along with its corresponding hex digest. An algorithm
        is considered "supported" if it is recognized as a valid hash algorithm in the `hashlib`
        library.

        If file size and/or checksum & checksum_algorithm values are provided, `store_object`
        validates the object to ensure it matches the given arguments before moving the file to
        its permanent address.

        :param str pid: Authority-based identifier.
        :param mixed data: String or path to the object.
        :param str additional_algorithm: Additional hex digest to include.
        :param str checksum: Checksum to validate against.
        :param str checksum_algorithm: Algorithm of the supplied checksum.
        :param int expected_object_size: Size of the object to verify.

        :return: ObjectMetadata - Object containing the permanent address, file size, and
            hex digest dictionary.
        """
        raise NotImplementedError()

    @abstractmethod
    def tag_object(self, pid, cid):
        """Creates references that allow objects stored in HashStore to be discoverable. Retrieving,
        deleting or calculating a hex digest of an object is based on a pid argument; and to
        proceed, we must be able to find the object associated with the pid.

        :param str pid: Authority-based or persistent identifier of the object.
        :param str cid: Content identifier of the object.

        :return: bool - `True` upon successful tagging.
        """
        raise NotImplementedError()

    @abstractmethod
    def verify_object(
        self, object_metadata, checksum, checksum_algorithm, expected_file_size
    ):
        """Confirm equality of content in an ObjectMetadata. The `verify_object` method verifies
        that the content in the provided `object_metadata` matches the specified values.

        :param ObjectMetadata object_metadata: ObjectMetadata object.
        :param str checksum: Value of the checksum.
        :param str checksum_algorithm: Algorithm of the checksum.
        :param int expected_file_size: Size of the temporary file.

        :return: bool - `True` if valid
        """
        raise NotImplementedError()

    @abstractmethod
    def find_object(self, pid):
        """Check if an object referenced by a pid exists and retrieve its content identifier.
        The `find_object` method validates the existence of an object based on the provided
        pid and returns the associated content identifier.

        :param str pid: Authority-based or persistent identifier of the object.

        :return: str - Content identifier of the object.
        """
        raise NotImplementedError()

    @abstractmethod
    def store_metadata(self, pid, metadata, format_id):
        """Add or update metadata, such as `sysmeta`, to disk using the given path/stream. The
        `store_metadata` method uses a persistent identifier `pid` and a metadata `format_id`
        to determine the permanent address of the metadata object. All metadata documents for a
        given `pid` will be stored in a directory (under ../metadata) that is determined by
        calculating the hash of the given pid, with the document name being the hash of the
        metadata format (`format_id`).

        Upon successful storage of metadata, the method returns a string representing the file's
        permanent address. Metadata objects are stored in parallel to objects in the
        `/store_directory/metadata/` directory.

        :param str pid: Authority-based identifier.
        :param mixed metadata: String or path to the metadata document.
        :param str format_id: Metadata format.

        :return: str - Address of the metadata document.
        """
        raise NotImplementedError()

    @abstractmethod
    def retrieve_object(self, pid):
        """Retrieve an object from disk using a persistent identifier (pid). The `retrieve_object`
        method opens and returns a buffered object stream ready for reading if the object
        associated with the provided `pid` exists on disk.

        :param str pid: Authority-based identifier.

        :return: io.BufferedReader - Buffered stream of the data object.
        """
        raise NotImplementedError()

    @abstractmethod
    def retrieve_metadata(self, pid, format_id):
        """Retrieve the metadata object from disk using a persistent identifier (pid)
        and metadata namespace (format_id). If the metadata document exists, the method opens
        and returns a buffered metadata stream ready for reading.

        :param str pid: Authority-based identifier.
        :param str format_id: Metadata format.

        :return: io.BufferedReader - Buffered stream of the metadata object.
        """
        raise NotImplementedError()

    @abstractmethod
    def delete_object(self, ab_id, id_type):
        """Deletes an object and its related data permanently from HashStore using a given
        persistent identifier. If the `id_type` is 'pid', the object associated with the pid will
        be deleted if it is not referenced by any other pids, along with its reference files and
        all metadata documents found in its respective metadata directory. If the `id_type` is
        'cid', only the object will be deleted if it is not referenced by other pids.

        :param str ab_id: Authority-based identifier.
        :param str id_type: "pid" or "Cid
        """
        raise NotImplementedError()

    @abstractmethod
    def delete_metadata(self, pid, format_id):
        """Deletes a metadata document (ex. `sysmeta`) permanently from HashStore using a given
        persistent identifier (`pid`) and format_id (metadata namespace). If a `format_id` is
        not supplied, all metadata documents associated with the given `pid` will be deleted.

        :param str pid: Authority-based identifier.
        :param str format_id: Metadata format.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_hex_digest(self, pid, algorithm):
        """Calculates the hex digest of an object that exists in HashStore using a given persistent
        identifier and hash algorithm.

        :param str pid: Authority-based identifier.
        :param str algorithm: Algorithm of hex digest to generate.

        :return: str - Hex digest of the object.
        """
        raise NotImplementedError()


class HashStoreFactory:
    """A factory class for creating `HashStore`-like objects.

    The `HashStoreFactory` class serves as a factory for creating `HashStore`-like objects,
    which are classes that implement the 'HashStore' abstract methods.

    This factory class provides a method to retrieve a `HashStore` object based on a given module
    (e.g., "hashstore.filehashstore.filehashstore") and class name (e.g., "FileHashStore").
    """

    @staticmethod
    def get_hashstore(module_name, class_name, properties=None):
        """Get a `HashStore`-like object based on the specified `module_name` and `class_name`.

        The `get_hashstore` method retrieves a `HashStore`-like object based on the provided
        `module_name` and `class_name`, with optional custom properties.

        :param str module_name: Name of the package (e.g., "hashstore.filehashstore").
        :param str class_name: Name of the class in the given module (e.g., "FileHashStore").
        :param dict properties: Desired HashStore properties (optional). If `None`, default values
            will be used. Example Properties Dictionary:
            {
                "store_path": "var/metacat",
                "store_depth": 3,
                "store_width": 2,
                "store_algorithm": "sha256",
                "store_sysmeta_namespace": "http://ns.dataone.org/service/types/v2.0"
            }

        :return: HashStore - A hash store object based on the given `module_name` and `class_name`.

        :raises ModuleNotFoundError: If the module is not found.
        :raises AttributeError: If the class does not exist within the module.
        """
        # Validate module
        if importlib.util.find_spec(module_name) is None:
            raise ModuleNotFoundError(f"No module found for '{module_name}'")

        # Get HashStore
        imported_module = importlib.import_module(module_name)

        # If class is not part of module, raise error
        if hasattr(imported_module, class_name):
            hashstore_class = getattr(imported_module, class_name)
            return hashstore_class(properties=properties)
        raise AttributeError(
            f"Class name '{class_name}' is not an attribute of module '{module_name}'"
        )


class ObjectMetadata(
    namedtuple("ObjectMetadata", ["pid", "cid", "obj_size", "hex_digests"])
):
    """Represents metadata associated with an object.

    The `ObjectMetadata` class represents metadata associated with an object, including
    a persistent or authority-based identifier (`pid`), a content identifier (`cid`),
    the size of the object in bytes (`obj_size`), and an optional list of hex digests
    (`hex_digests`) to assist with validating objects.

    :param str cid: A unique identifier for the object (Hash ID, hex digest).
    :param bytes obj_size: The size of the object in bytes.
    :param list hex_digests: A list of hex digests to validate objects
        (md5, sha1, sha256, sha384, sha512) (optional).
    """

    # Default value to prevent dangerous default value
    def __new__(cls, pid, cid, obj_size, hex_digests=None):
        return super(ObjectMetadata, cls).__new__(cls, pid, cid, obj_size, hex_digests)
