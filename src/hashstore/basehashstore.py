"""Hashstore Interface"""

import importlib.metadata
import importlib.util
from abc import ABC, abstractmethod
from collections.abc import Generator
from typing import IO

import hashstore.folderentry


class HashStore(ABC):
    """HashStore is a content-addressable file management
    system that utilizes an object's content identifier (hex digest/checksum) to
    address files."""

    @staticmethod
    def version():
        """Return the version number"""
        return importlib.metadata.version("hashstore")

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
        """Atomic storage of objects to disk using a given stream. Upon
        successful storage, it returns an `ObjectMetadata` object containing
        relevant file information, such as a persistent identifier that
        references the data file, the file's size, and a hex digest dictionary
        of algorithms and checksums. The method also tags the object, creating
        references for discoverability.

        `store_object` ensures that an object is stored only once by
        synchronizing multiple calls and rejecting attempts to store duplicate
        objects. If called without a pid, it stores the object without tagging,
        and it becomes the caller's responsibility to finalize the process by
        calling `tag_object` after verifying the correct object is stored.

        The file's permanent address is determined by calculating the object's
        content identifier based on the store's default algorithm, which is also
        the permanent address of the file. The content identifier is then
        sharded using the store's configured depth and width, delimited by '/',
        and concatenated to produce the final permanent address. This address is
        stored in the `/store_directory/objects/` directory.

        By default, the hex digest map includes common hash algorithms (md5,
        sha1, sha256, sha384, sha512). If an additional algorithm is provided,
        the method checks if it is supported and adds it to the hex digests
        dictionary along with its corresponding hex digest. An algorithm is
        considered "supported" if it is recognized as a valid hash algorithm in
        the `hashlib` library.

        If file size and/or checksum & checksum_algorithm values are provided,
        `store_object` validates the object to ensure it matches the given
        arguments before moving the file to its permanent address.

        :param str pid: Authority-based identifier.
        :param mixed data: String or path to the object.
        :param str additional_algorithm: Additional hex digest to include.
        :param str checksum: Checksum to validate against.
        :param str checksum_algorithm: Algorithm of the supplied checksum.
        :param int expected_object_size: Size of the object to verify.

        :return: ObjectMetadata - Object containing the persistent identifier (pid),
        content identifier (cid), object size and hex digests dictionary (checksums).
        """
        raise NotImplementedError()

    @abstractmethod
    def resolve_pidpath(self, pidpath: list[str]) -> dict[str, str]:
        """Return object info dict given a path.

        A path may reference another path:
            c_1 -> sub_1 -> c_0 -> sub_2 -> x
        In such cases, the full path is not stored as a cidref, instead
        we have:
            path           name
            c_1            sub_1
            c_1, sub_1     c_0      <- change of context
            c_0            sub_2
            c_0, sub_2     x
            c_0, sub_2, x

        Hence it is necessary to walk the path to find the next context,
        switch to that context, then continue looking for the target.

        An alternative strategy is to load the CID from each folder along
        the path, but that is more IO and iterations to find the target.
        """
        raise NotADirectoryError()

    @abstractmethod
    def store_folder(
        self,
        pidpath: list[str],
        entries: hashstore.folderentry.FolderEntries,
        additional_algorithm: str | None = None,
        checksum: str | None = None,
        checksum_algorithm: str | None = None,
        verify_entry_cids: bool = True,
    ):
        """Store a folder object.

        A Folder is a list of entries that appear in a folder. Each entry
        may be a file or a Folder. This method is used instead of store_object
        because Folders have special requirements to ensure deterministic serialization.

        The Folder is tagged with an identifier that is "{PID} {path}", that is, the
        PID followed by a single space, then the path. If the path portion is an empty
        string, ".", or "/" then the Folder is the root Folder.

        Note that since the hash of a Folder is computed from hashes of its content,
        a Folder hierarchy must be stored starting with the leaves. This method
        will raise a ValueError if the hash of an entry does not already exist in
        the hashstore. Hence the general pattern for storing a folder hierarchy is
        to do a depth first traversal of the hierarchy, storing the files (ensuring
        their hashes are available) and computing the hash for the containing folder
        for use in the parent folder reference to the child.

        Args:
            pid (str): The context within which this folder is being stored
            path (str): Path to this folder relative to the root.
            entries (list[FolderEntry]): A list of FolderEntry objects.
            verify_entry_cids: If True then FolderEntry CID values are
                verified to to ensure they exist in the hashstore.

        Returns:
            ObjectMetadata: The computed ObjectMetadata for this entry.

        Raises:
            NotImplementedError: Must be implemented in subclass.
        """
        raise NotImplementedError()

    @abstractmethod
    def retrieve_folder(
        self,
        pidpath: list[str],
    ) -> hashstore.folderentry.FolderEntries:
        """Retrieve a FolderEntries instance from the hashstore.

        We first check to see if a CID is available for the combination of
        "{PID} {path}", and if so, return that entry. Otherwise, we iterate
        over path segments to find the correspoding FolderEntry, if any.
        This iterative approach is necesary if since entire trees are not
        stored when a new version of a folder hierarchy is stored. Hence, it
        may be necessary to jump back to a branch that is recorded in an
        earlier version but not recorded in the current version since it
        was unchanged between versions.

        Args:
            pid (str): The context (i.e. VMDAG version) within which this folder is
                being retrieved
            path (str): Path within the context to the desired entry
        Returns:
            FolderEntries
        """
        raise NotImplementedError()

    @abstractmethod
    def tag_object(self, pid, cid):
        """Creates references that allow objects stored in HashStore to be discoverable.
        Retrieving, deleting or calculating a hex digest of an object is based
        on a pid argument, to proceed, we must be able to find the object
        associated with the pid.

        :param str pid: Authority-based or persistent identifier of the object.
        :param str cid: Content identifier of the object.
        """
        raise NotImplementedError()

    @abstractmethod
    def store_metadata(self, pid, metadata, format_id):
        """Add or update metadata, such as `sysmeta`, to disk using the given
        path/stream. The `store_metadata` method uses a persistent identifier
        `pid` and a metadata `format_id` to determine the permanent address of
        the metadata object. All metadata documents for a given `pid` will be
        stored in a directory that follows the HashStore configuration settings
        (under ../metadata) that is determined by calculating the hash of the
        given pid. Metadata documents are stored in this directory, and is each
        named using the hash of the pid and metadata format (`pid` +
        `format_id`).

        Upon successful storage of metadata, the method returns a string
        representing the file's permanent address. Metadata objects are stored
        in parallel to objects in the `/store_directory/metadata/` directory.

        :param str pid: Authority-based identifier.
        :param mixed metadata: String or path to the metadata document.
        :param str format_id: Metadata format.

        :return: str - Address of the metadata document.
        """
        raise NotImplementedError()

    @abstractmethod
    def retrieve_object(self, pid):
        """Retrieve an object from disk using a persistent identifier (pid). The
        `retrieve_object` method opens and returns a buffered object stream
        ready for reading if the object associated with the provided `pid`
        exists on disk.

        :param str pid: Authority-based identifier.

        :return: io.BufferedReader - Buffered stream of the data object.
        """
        raise NotImplementedError()

    @abstractmethod
    def retrieve_object_path(self, pidpath: list[str]) -> IO[bytes]:
        """Retrieve an object from disk using a persistent identifier (pid). The
        `retrieve_object` method opens and returns a buffered object stream ready
        for reading if the object associated with the provided `pid` exists on disk.

        :param str pid: Authority-based identifier.

        :return: io.BufferedReader - Buffered stream of the data object.
        """
        raise NotImplementedError()

    @abstractmethod
    def retrieve_metadata(self, pid, format_id):
        """Retrieve the metadata object from disk using a persistent identifier
        (pid) and metadata namespace (format_id). If the metadata document
        exists, the method opens and returns a buffered metadata stream ready
        for reading.

        :param str pid: Authority-based identifier.
        :param str format_id: Metadata format.

        :return: io.BufferedReader - Buffered stream of the metadata object.
        """
        raise NotImplementedError()

    @abstractmethod
    def delete_object(self, pid):
        """Deletes an object and its related data permanently from HashStore
        using a given persistent identifier. The object associated with the pid
        will be deleted if it is not referenced by any other pids, along with
        its reference files and all metadata documents found in its respective
        metadata directory.

        :param str pid: Persistent or Authority-based identifier.
        """
        raise NotImplementedError()

    @abstractmethod
    def delete_if_invalid_object(
        self, object_metadata, checksum, checksum_algorithm, expected_file_size
    ):
        """Confirm equality of content in an ObjectMetadata. The
        `delete_invalid_object` method will delete a data object if the
        object_metadata does not match the specified values.

        :param ObjectMetadata object_metadata: ObjectMetadata object.
        :param str checksum: Value of the checksum.
        :param str checksum_algorithm: Algorithm of the checksum.
        :param int expected_file_size: Size of the temporary file.
        """
        raise NotImplementedError()

    @abstractmethod
    def delete_metadata(self, pid, format_id):
        """Deletes a metadata document (ex. `sysmeta`) permanently from
        HashStore using a given persistent identifier (`pid`) and format_id
        (metadata namespace). If a `format_id` is not supplied, all metadata
        documents associated with the given `pid` will be deleted.

        :param str pid: Authority-based identifier.
        :param str format_id: Metadata format.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_hex_digest(self, pid, algorithm):
        """Calculates the hex digest of an object that exists in HashStore using
        a given persistent identifier and hash algorithm.

        :param str pid: Authority-based identifier.
        :param str algorithm: Algorithm of hex digest to generate.

        :return: str - Hex digest of the object.
        """
        raise NotImplementedError()

    @abstractmethod
    def list_pids(self, pattern: str | None = None) -> Generator:
        """Yields PIDs from the hashstore.

        :param str pattern: Optional regexp pattern to match.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_object_status(self, pid) -> dict:
        """Returns a dictionary of the object size, modtime, accesstime for the given
        pid.

        :param str pid: Object identifier

        :return: dict - Dictionary containing information about the object.
        """
        raise NotImplementedError()

    @abstractmethod
    def find_object(self, pid: str) -> dict[str, str]:
        """Check if an object referenced by a pid exists and retrieve its content
        identifier.

        The `find_object` method validates the existence of an object based on the
        provided pid and returns the associated content identifier and information
        about how to retrieve various accoutrements. Note that the returned dict will
        contain values relevant to the type of store, but will always contain a `cid`
        key if the object is present.

        :param str pid: Authority-based or persistent identifier of the object.

        :return: obj_info_dict:
            - cid: content identifier
            - cid_object_path: path to the object
            - cid_refs_path: path to the cid refs file
            - pid_refs_path: path to the pid refs file
            - sysmeta_path: path to the sysmeta file
        """
        raise NotImplementedError()


class HashStoreFactory:
    """A factory class for creating `HashStore`-like objects.

    The `HashStoreFactory` class serves as a factory for creating
    `HashStore`-like objects, which are classes that implement the 'HashStore'
    abstract methods.

    This factory class provides a method to retrieve a `HashStore` object based
    on a given module (e.g., "hashstore.filehashstore.filehashstore") and class
    name (e.g., "FileHashStore")."""

    @staticmethod
    def get_hashstore(module_name, class_name, properties=None):
        """Get a `HashStore`-like object based on the specified `module_name`
        and `class_name`.

        The `get_hashstore` method retrieves a `HashStore`-like object based on
        the provided `module_name` and `class_name`, with optional custom
        properties.

        :param str module_name: Name of the package (e.g., "hashstore.filehashstore").
        :param str class_name: Name of the class in the given module
            (e.g., "FileHashStore").
        :param dict properties: Desired HashStore properties (optional). If `None`,
            default values will be used. Example Properties Dictionary:
            {
                "store_path": "var/metacat",
                "store_depth": 3,
                "store_width": 2,
                "store_algorithm": "SHA-256",
                "store_metadata_namespace": "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
            }

        :return: HashStore - A hash store object based on the given `module_name`
            and `class_name`.

        :raises ModuleNotFoundError: If the module is not found.
        :raises AttributeError: If the class does not exist within the module.
        """
        # Validate module
        if importlib.util.find_spec(module_name) is None:
            msg = f"No module found for '{module_name}'"
            raise ModuleNotFoundError(msg)

        # Get HashStore
        imported_module = importlib.import_module(module_name)

        # If class is not part of module, raise error
        if hasattr(imported_module, class_name):
            hashstore_class = getattr(imported_module, class_name)
            return hashstore_class(properties=properties)
        msg = f"Class name '{class_name}' is not an attribute of module '{module_name}'"
        raise AttributeError(msg)
