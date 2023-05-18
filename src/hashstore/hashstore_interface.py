"""Hashstore Interface"""
from abc import ABC, abstractmethod


class HashStoreInterface(ABC):
    """HashStore is a content-addressable file management system that
    utilizes a persistent identifier (PID) in the form of a hex digest
    value to address files."""

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
        relevant file information, such as the file's id, relative path, absolute
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
        is recognized as a valid hash algorithm in the `hashlib` libary.

        Similarly, if a checksum and a checksumAlgorithm value are provided,
        `store_object` validates the object to ensure it matches what is provided
        before moving the file to its permanent address.

        Args:
            pid (string): Authority-based identifier. \n
            data (mixed): String or path to object. \n
            additional_algorithm (string): Additional hex digest to include. \n
            checksum (string): Checksum to validate against. \n
            checksum_algorithm (string): Algorithm of supplied checksum.

        Returns:
            address (HashAddress): Object that contains the permanent address, relative
            file path, absolute file path, duplicate file boolean and hex digest dictionary.
        """
        raise NotImplementedError()

    @abstractmethod
    def store_sysmeta(self, pid, sysmeta):
        """The `store_sysmeta` method is responsible for adding and/or updating metadata
        (`sysmeta`) to disk using a given InputStream and a persistent identifier
        (pid). The metadata object consists of a header and body portion. The header
        is formed by writing the namespace/format (utf-8) of the metadata document
        followed by a null character `\x00` and the body follows immediately after.

        Upon successful storage of sysmeta, the method returns a String that
        represents the file's permanent address, and similarly to 'store_object', this
        permanent address is determined by calculating the SHA-256 hex digest of the
        provided pid. Finally, sysmeta are stored in parallel to objects in the
        `/store_directory/sysmeta/` directory.

        Args:
            pid (string): Authority-based identifier. \n
            sysmeta (mixed): String or path to sysmeta document.

        Returns:
            sysmeta_cid (string): Address of the sysmeta document.
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
            obj_stream (io.BufferedReader): A buffered stream of an ab_id object.
        """
        raise NotImplementedError()

    @abstractmethod
    def retrieve_sysmeta(self, pid):
        """The 'retrieve_sysmeta' method retrieves the metadata content from disk and
        returns it in the form of a String using a given persistent identifier.

        Args:
            pid (string): Authority-based identifier.

        Returns:
            sysmeta (string): Sysmeta content.
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
    def delete_sysmeta(self, pid):
        """The 'delete_sysmeta' method deletes an metadata document (sysmeta) permanently
        from disk using a given persistent identifier.

        Args:
            pid (string): Authority-based identifier.

        Returns:
            boolean: `True` upon successful deletion.
        """
        raise NotImplementedError()

    @abstractmethod
    def get_hex_digest(self, pid, algorithm):
        """The 'get_hex_digest' method calculates the hex digest of an object that exists
        in HashStore using a given persistent identifier and hash algorithm.

        Args:
            pid (string): Authority-based identifier. \n
            algorithm (string): Algorithm of hex digest to generate.

        Returns:
            hex_digest (string): Hex digest of the object.
        """
        raise NotImplementedError()
