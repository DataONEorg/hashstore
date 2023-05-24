"""Core module for HashStore Factory"""
import importlib


class HashStoreFactory:
    """A factory class for creating `HashStore`-like objects (classes
    that implement the 'HashStore' abstract methods)

    This factory class provides a method to retrieve a `HashStore` object
    based on a given module (ex. "hashstore.filehashstore.filehashstore")
    and class name (ex. "FileHashStore").
    """

    def __init__(self):
        """Initialize the HashStoreFactory with default config values"""
        # TODO: Add logging

    @staticmethod
    def get_hashstore(module_name, class_name):
        """Get a `HashStore`-like object based on the specified store type.

        Args:
            module_name (str): Name of module/package (ex. "hashstore.filehashstore.filehashstore")
            class_name (str): Name of class in the given module (ex. "FileHashStore")

        Returns:
            HashStore: A hash store object based on the given store type.

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
            return hashstore_class()
        else:
            raise AttributeError(
                f"Class name '{class_name}' is not an attribute of module '{module_name}'"
            )
