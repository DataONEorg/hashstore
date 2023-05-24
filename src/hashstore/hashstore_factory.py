"""Core module for HashStore Factory"""
import importlib


class HashStoreFactory:
    """A factory class for creating `HashStore`-like objects (classes
    that implement the 'HashStore' abstract methods)

    This factory class provides a method to retrieve a `HashStore` object
    based on the specified store type (ex. "FileHashStore"). It supports the
    creation of different types of hash stores by mapping store types to
    specific implementations.
    """

    def __init__(self):
        """Initialize the HashStoreFactory with default config values"""
        # TODO: Add logging

    @staticmethod
    def get_hashstore(hashstore_type):
        """Get a `HashStore`-like object based on the specified store type.

        Args:
            hashstore_type (str): The type of `HashStore` to retrieve.

        Returns:
            HashStore: A hash store object based on the given store type.

        Raises:
            ValueError: If the given store_type is not supported.
        """

        if hashstore_type.lower() == "filehashstore":
            module_name = "hashstore.filehashstore.filehashstore"
            class_name = "FileHashStore"
            imported_module = importlib.import_module(module_name)
            hashstore_class = getattr(imported_module, class_name)
            return hashstore_class()
        else:
            raise ValueError(f"hashstore_type: {hashstore_type} is not supported.")
