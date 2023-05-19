"""Core module for HashStore Factory"""
from hashstore.filehashstore.filehashstore import FileHashStore


class HashStoreFactory:
    """A factory class for creating `HashStore`-like objects (classes
    that implement the 'hashstore' abstract methods)

    This factory class provides a method to retrieve a `hashstore` object
    based on the specified store type (ex. "filehashstore"). It supports the
    creation of different types of hash stores by mapping store types to
    specific implementations.
    """

    def __init__(self):
        """Initialize the HashStoreFactory with default config values"""
        # TODO: Add logging

    def get_hashstore(self, hashstore_type):
        """Get a `HashStore`-like object based on the specified store type.

        Args:
            hashstore_type (str): The type of `HashStore` to retrieve.

        Returns:
            HashStore: A hash store object based on the given store type.

        Raises:
            ValueError: If the given store_type is not supported.
        """
        hashstore_type.lower()
        if hashstore_type == "filehashstore":
            return FileHashStore()
        else:
            raise ValueError(f"hashstore_type: {hashstore_type} is not supported.")
