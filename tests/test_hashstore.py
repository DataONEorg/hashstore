"""Test module for HashStore (and HashStoreFactory)"""
import pytest
from hashstore.filehashstore.filehashstore import FileHashStore
from hashstore.hashstore_factory import HashStoreFactory

@pytest.fixture(name="props")
def init_props(tmp_path):
    """Create store path for all tests"""
    directory = tmp_path / "metacat"
    directory.mkdir()
    hashstore_path = directory.as_posix()
    # Note, objects generated via tests are placed in a temporary folder
    # with the 'directory' parameter above appended
    properties = {
        "store_path": hashstore_path,
        "store_depth": 3,
        "store_width": 2,
        "store_algorithm": "sha256",
        "store_sysmeta_namespace": "http://ns.dataone.org/service/types/v2.0",
    }
    return properties


@pytest.fixture(name="factory")
def init_factory():
    """Create factory for all tests"""
    factory = HashStoreFactory()
    return factory


def test_init(factory):
    """Check Hashstore Factory exists"""
    assert isinstance(factory, HashStoreFactory)


def test_factory_get_hashstore_filehashstore(factory, props):
    """Check factory creates instance of FileHashStore"""
    module_name = "hashstore.filehashstore.filehashstore"
    class_name = "FileHashStore"
    store = factory.get_hashstore(module_name, class_name, props)
    assert isinstance(store, FileHashStore)


def test_factory_get_hashstore_unsupported_class(factory):
    """Check that AttributeError is raised when provided with unsupported class"""
    with pytest.raises(AttributeError):
        module_name = "hashstore.filehashstore.filehashstore"
        class_name = "S3HashStore"
        factory.get_hashstore(module_name, class_name)


def test_factory_get_hashstore_unsupported_module(factory):
    """Check that ModuleNotFoundError is raised when provided with unsupported module"""
    with pytest.raises(ModuleNotFoundError):
        module_name = "hashstore.s3filestore.s3filestore"
        class_name = "FileHashStore"
        factory.get_hashstore(module_name, class_name)
