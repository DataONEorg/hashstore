"""Test module for HashStore (and HashStoreFactory)"""
import importlib.metadata
import pytest
from hashstore.filehashstore.filehashstore import FileHashStore
from hashstore.hashstore_factory import HashStoreFactory


@pytest.fixture(name="store")
def init_store():
    """Create store path for all tests"""
    # TODO: Replace with relevant test after updating factory __init__
    store = FileHashStore()
    return store


def test_init(store):
    """Check Hashstore initialization"""
    value = store.version()
    assert value == importlib.metadata.version("hashstore")
    # TODO: Revise test to check that root folder exists when
    #       HashStore object path details confirmed
    # assert os.path.exists(store.root)


def test_factory():
    """Check factory exists"""
    factory = HashStoreFactory()
    assert isinstance(factory, HashStoreFactory)


def test_factory_get_hashstore_filehashstore():
    """Check factory creates instance of FileHashStore"""
    factory = HashStoreFactory()
    module_name = "hashstore.filehashstore.filehashstore"
    class_name = "FileHashStore"
    store = factory.get_hashstore(module_name, class_name)
    assert isinstance(store, FileHashStore)


def test_factory_get_hashstore_unsupported_class():
    """Check that AttributeError is raised when provided with unsupported class"""
    factory = HashStoreFactory()
    with pytest.raises(AttributeError):
        module_name = "hashstore.filehashstore.filehashstore"
        class_name = "S3HashStore"
        factory.get_hashstore(module_name, class_name)


def test_factory_get_hashstore_unsupported_module():
    """Check that ModuleNotFoundError is raised when provided with unsupported module"""
    factory = HashStoreFactory()
    with pytest.raises(ModuleNotFoundError):
        module_name = "hashstore.s3filestore.s3filestore"
        class_name = "FileHashStore"
        factory.get_hashstore(module_name, class_name)
