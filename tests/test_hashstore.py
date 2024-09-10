"""Test module for HashStore's HashStoreFactory and ObjectMetadata class."""

import os
import pytest
from hashstore.hashstore import HashStoreFactory
from hashstore.filehashstore import FileHashStore


@pytest.fixture(name="factory")
def init_factory():
    """Create factory for all tests."""
    factory = HashStoreFactory()
    return factory


def test_init(factory):
    """Check Hashstore Factory exists."""
    assert isinstance(factory, HashStoreFactory)


def test_factory_get_hashstore_filehashstore(factory, props):
    """Check factory creates instance of FileHashStore."""
    module_name = "hashstore.filehashstore"
    class_name = "FileHashStore"
    # These props can be found in tests/conftest.py
    store = factory.get_hashstore(module_name, class_name, props)
    assert isinstance(store, FileHashStore)


def test_factory_get_hashstore_unsupported_class(factory):
    """Check that AttributeError is raised when provided with unsupported class."""
    with pytest.raises(AttributeError):
        module_name = "hashstore.filehashstore"
        class_name = "S3HashStore"
        factory.get_hashstore(module_name, class_name)


def test_factory_get_hashstore_unsupported_module(factory):
    """Check that ModuleNotFoundError is raised when provided with unsupported module."""
    with pytest.raises(ModuleNotFoundError):
        module_name = "hashstore.s3filestore"
        class_name = "FileHashStore"
        factory.get_hashstore(module_name, class_name)


def test_factory_get_hashstore_filehashstore_unsupported_algorithm(factory):
    """Check factory raises exception with store algorithm value that is not part of
    the default list."""
    module_name = "hashstore.filehashstore"
    class_name = "FileHashStore"

    properties = {
        "store_path": os.getcwd() + "/metacat/hashstore",
        "store_depth": 3,
        "store_width": 2,
        "store_algorithm": "MD2",
        "store_metadata_namespace": "https://ns.dataone.org/service/types/v2.0#SystemMetadata",
    }
    with pytest.raises(ValueError):
        factory.get_hashstore(module_name, class_name, properties)


def test_factory_get_hashstore_filehashstore_incorrect_algorithm_format(factory):
    """Check factory raises exception with incorrectly formatted algorithm value."""
    module_name = "hashstore.filehashstore"
    class_name = "FileHashStore"

    properties = {
        "store_path": os.getcwd() + "/metacat/hashstore",
        "store_depth": 3,
        "store_width": 2,
        "store_algorithm": "dou_algo",
        "store_metadata_namespace": "https://ns.dataone.org/service/types/v2.0#SystemMetadata",
    }
    with pytest.raises(ValueError):
        factory.get_hashstore(module_name, class_name, properties)


def test_factory_get_hashstore_filehashstore_conflicting_obj_dir(factory, tmp_path):
    """Check factory raises exception when existing `/objects` directory exists."""
    module_name = "hashstore.filehashstore"
    class_name = "FileHashStore"

    directory = tmp_path / "douhs" / "objects"
    directory.mkdir(parents=True)
    douhspath = (tmp_path / "douhs").as_posix()

    properties = {
        "store_path": douhspath,
        "store_depth": 3,
        "store_width": 2,
        "store_algorithm": "SHA-256",
        "store_metadata_namespace": "https://ns.dataone.org/service/types/v2.0#SystemMetadata",
    }
    with pytest.raises(RuntimeError):
        factory.get_hashstore(module_name, class_name, properties)


def test_factory_get_hashstore_filehashstore_conflicting_metadata_dir(
    factory, tmp_path
):
    """Check factory raises exception when existing `/metadata` directory exists."""
    module_name = "hashstore.filehashstore"
    class_name = "FileHashStore"

    directory = tmp_path / "douhs" / "metadata"
    directory.mkdir(parents=True)
    douhspath = (tmp_path / "douhs").as_posix()

    properties = {
        "store_path": douhspath,
        "store_depth": 3,
        "store_width": 2,
        "store_algorithm": "SHA-256",
        "store_metadata_namespace": "https://ns.dataone.org/service/types/v2.0#SystemMetadata",
    }
    with pytest.raises(RuntimeError):
        factory.get_hashstore(module_name, class_name, properties)


def test_factory_get_hashstore_filehashstore_conflicting_refs_dir(factory, tmp_path):
    """Check factory raises exception when existing `/refs` directory exists."""
    module_name = "hashstore.filehashstore"
    class_name = "FileHashStore"

    directory = tmp_path / "douhs" / "refs"
    directory.mkdir(parents=True)
    douhspath = (tmp_path / "douhs").as_posix()

    properties = {
        "store_path": douhspath,
        "store_depth": 3,
        "store_width": 2,
        "store_algorithm": "SHA-256",
        "store_metadata_namespace": "https://ns.dataone.org/service/types/v2.0#SystemMetadata",
    }
    with pytest.raises(RuntimeError):
        factory.get_hashstore(module_name, class_name, properties)


def test_factory_get_hashstore_filehashstore_nonconflicting_dir(factory, tmp_path):
    """Check factory does not raise exception when existing non-conflicting directory exists."""
    module_name = "hashstore.filehashstore"
    class_name = "FileHashStore"

    directory = tmp_path / "douhs" / "other"
    directory.mkdir(parents=True)
    douhspath = (tmp_path / "douhs").as_posix()

    properties = {
        "store_path": douhspath,
        "store_depth": 3,
        "store_width": 2,
        "store_algorithm": "SHA-256",
        "store_metadata_namespace": "https://ns.dataone.org/service/types/v2.0#SystemMetadata",
    }

    factory.get_hashstore(module_name, class_name, properties)


def test_factory_get_hashstore_filehashstore_string_int_prop(factory, tmp_path):
    """Check factory does not raise exception when an integer is passed as a string in a
    properties object."""
    module_name = "hashstore.filehashstore"
    class_name = "FileHashStore"

    directory = tmp_path / "douhs" / "inttest"
    directory.mkdir(parents=True)
    douhspath = (tmp_path / "douhs").as_posix()

    properties = {
        "store_path": douhspath,
        "store_depth": "3",
        "store_width": "2",
        "store_algorithm": "SHA-256",
        "store_metadata_namespace": "https://ns.dataone.org/service/types/v2.0#SystemMetadata",
    }

    factory.get_hashstore(module_name, class_name, properties)

    properties = {
        "store_path": douhspath,
        "store_depth": str(3),
        "store_width": str(2),
        "store_algorithm": "SHA-256",
        "store_metadata_namespace": "https://ns.dataone.org/service/types/v2.0#SystemMetadata",
    }

    factory.get_hashstore(module_name, class_name, properties)
