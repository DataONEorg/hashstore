"""Hashstore Interface"""
from abc import ABC, abstractmethod
from collections import namedtuple
import importlib.metadata


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
        """The `store_object` method is responsible for the atomic storage of objects to
        disk using a given stream. Upon successful storage, the method returns a ObjectMetadata
        object containing relevant file information, such as the file's id (which can be
        used to locate the object on disk), the file's size, and a hex digest dict of algorithms
        and checksums. `store_object` also ensures that an object is stored only once by
        synchronizing multiple calls and rejecting calls to store duplicate objects. Lastly,
        it should call `tag_object` to create the references to allow the object to be found.

        The file's id is determined by calculating the object's content identifier based on
        the store's default algorithm, which is also used as the permanent address of the file.
        The file's identifier is then sharded using the store's configured depth and width,
        delimited by '/' and concatenated to produce the final permanent address
        and is stored in the `/store_directory/objects/` directory.

        By default, the hex digest map includes the following hash algorithms:
        md5, sha1, sha256, sha384, sha512 - which are the most commonly used algorithms in
        dataset submissions to DataONE and the Arctic Data Center. If an additional algorithm
        is provided, the `store_object` method checks if it is supported and adds it to the
        hex digests dict along with its corresponding hex digest. An algorithm is considered
        "supported" if it is recognized as a valid hash algorithm in the `hashlib` library.

        Similarly, if a file size and/or checksum & checksum_algorithm value are provided,
        `store_object` validates the object to ensure it matches the given arguments
        before moving the file to its permanent address.

        Note, calling `store_object` is a possibility, but should only store the object
        without calling `tag_object`. It is the caller's responsibility to finalize the
        process by calling `tag_object` after veriftying the correct object is stored.

        Args:
            pid (string): Authority-based identifier.
            data (mixed): String or path to object.
            additional_algorithm (string): Additional hex digest to include.
            checksum (string): Checksum to validate against.
            checksum_algorithm (string): Algorithm of supplied checksum.
            expected_object_size (int): Size of object to verify

        Returns:
            object_metadata (ObjectMetadata): Object that contains the permanent address,
            file size and hex digest dictionary.
        """
        raise NotImplementedError()

    @abstractmethod
    def tag_object(self, pid, cid):
        """The `tag_object` method creates references that allow objects stored in HashStore
        to be discoverable. Retrieving, deleting or calculating a hex digest of an object is
        based on a pid argument; and to proceed, we must be able to find the object associated
        with the pid.

        Args:
            pid (string): Authority-based or persistent identifier of object
            cid (string): Content identifier of object

        Returns:
            boolean: `True` upon successful tagging.
        """
        raise NotImplementedError()

    @abstractmethod
    def find_object(self, pid):
        """The `find_object` method checks whether an object referenced by a pid exists
        and returns the content identifier.

        Args:
            pid (string): Authority-based or persistent identifier of object

        Returns:
            cid (string): Content identifier of the object
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
        persistent identifier (pid). If the object exists, the method will open and return
        a buffered object stream ready to read from.

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


class HashStoreFactory:
    """A factory class for creating `HashStore`-like objects (classes
    that implement the 'HashStore' abstract methods)

    This factory class provides a method to retrieve a `HashStore` object
    based on a given module (ex. "hashstore.filehashstore.filehashstore")
    and class name (ex. "FileHashStore").
    """

    @staticmethod
    def get_hashstore(module_name, class_name, properties=None):
        """Get a `HashStore`-like object based on the specified `module_name` and `class_name`.

        Args:
            module_name (str): Name of package (ex. "hashstore.filehashstore") \n
            class_name (str): Name of class in the given module (ex. "FileHashStore") \n
            properties (dict, optional): Desired HashStore properties, if 'None', default values
            will be used. \n
                Example Properties Dictionary:
                {
                    "store_path": "var/metacat",\n
                    "store_depth": 3,\n
                    "store_width": 2,\n
                    "store_algorithm": "sha256",\n
                    "store_sysmeta_namespace": "http://ns.dataone.org/service/types/v2.0"\n
                }

        Returns:
            HashStore: A hash store object based on the given `module_name` and `class_name`

        Raises:
            ModuleNotFoundError: If module is not found
            AttributeError: If class does not exist within the module
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


class ObjectMetadata(namedtuple("ObjectMetadata", ["id", "obj_size", "hex_digests"])):
    """File address containing file's path on disk and its content hash ID.

    Args:
        ab_id (str): Hash ID (hexdigest) of file contents.
        obj_size (bytes): Size of the object
        hex_digests (dict, optional): A list of hex digests to validate objects
            (md5, sha1, sha256, sha384, sha512)
    """

    # Default value to prevent dangerous default value
    def __new__(cls, ab_id, obj_size, hex_digests=None):
        return super(ObjectMetadata, cls).__new__(cls, ab_id, obj_size, hex_digests)
