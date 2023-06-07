"""Test module for HashStore (and HashStoreFactory)"""
import pytest
from hashstore.filehashstore.filehashstore import FileHashStore
from hashstore.hashstore_factory import HashStoreFactory


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
    module_name = "hashstore.filehashstore.filehashstore"
    class_name = "FileHashStore"
    # These props can be found in tests/conftest.py
    store = factory.get_hashstore(module_name, class_name, props)
    assert isinstance(store, FileHashStore)


def test_factory_get_hashstore_unsupported_class(factory):
    """Check that AttributeError is raised when provided with unsupported class."""
    with pytest.raises(AttributeError):
        module_name = "hashstore.filehashstore.filehashstore"
        class_name = "S3HashStore"
        factory.get_hashstore(module_name, class_name)


def test_factory_get_hashstore_unsupported_module(factory):
    """Check that ModuleNotFoundError is raised when provided with unsupported module."""
    with pytest.raises(ModuleNotFoundError):
        module_name = "hashstore.s3filestore.s3filestore"
        class_name = "FileHashStore"
        factory.get_hashstore(module_name, class_name)
