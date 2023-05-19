"""Test module for HashStore (and HashStoreFactory)"""
import importlib.metadata
import pytest
from hashstore.filehashstore.filehashstore import FileHashStore
from hashstore.hashstore_factory import HashStoreFactory


@pytest.fixture(name="store")
def init_store():
    """Create store path for all tests"""
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
    hashstore_type = "filehashstore"
    factory = HashStoreFactory()
    store = factory.get_hashstore(hashstore_type)
    assert isinstance(store, FileHashStore)


def test_factory_get_hashstore_unsupported_fs():
    """Check that ValueError is raised when provided with unsupported store type"""
    hashstore_type = "s3hashstore"
    factory = HashStoreFactory()
    with pytest.raises(ValueError):
        factory.get_hashstore(hashstore_type)
