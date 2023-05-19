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


def test_factory(tmp_path):
    """Check factory exists"""
    directory = tmp_path / "metacat"
    directory.mkdir()
    # Get factory and hashstore
    factory = HashStoreFactory()
    assert isinstance(factory, HashStoreFactory)


def test_factory_get_hashstore_filehashstore(tmp_path):
    """Check factory creates instance of FileHashStore"""
    directory = tmp_path / "metacat"
    directory.mkdir()
    hashstore_type = "filehashstore"
    # Get factory and hashstore
    factory = HashStoreFactory()
    store = factory.get_hashstore(hashstore_type)
    assert isinstance(store, FileHashStore)


def test_factory_get_hashstore_unsupported_fs(tmp_path):
    """Check that ValueError is raised when provided with unsupported store type"""
    directory = tmp_path / "metacat"
    directory.mkdir()
    hashstore_type = "s3hashstore"
    factory = HashStoreFactory()
    with pytest.raises(ValueError):
        factory.get_hashstore(hashstore_type)
