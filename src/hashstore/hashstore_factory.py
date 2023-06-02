"""Core module for HashStore Factory"""
import importlib


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
            module_name (str): Name of module/package (ex. "hashstore.filehashstore.filehashstore") \n
            class_name (str): Name of class in the given module (ex. "FileHashStore") \n
            properties (dict, optional): Desired HashStore properties, if 'None', default values
            will be used. \n
                Example Properties Dictionary:
                {
                    "store_path": "var/metacat",
                    "store_depth": 3,
                    "store_width": 2,
                    "store_algorithm": "sha256",
                    "store_sysmeta_namespace": "http://ns.dataone.org/service/types/v2.0"
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
