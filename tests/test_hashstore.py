from hashstore import HashStore
from pathlib import Path
import hashlib
import importlib.metadata
import pytest


@pytest.fixture
def pids():
    pids = {
        "doi:10.18739/A2901ZH2M": "0d555ed77052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e",
        "jtao.1700.1": "a8241925740d5dcd719596639e780e0a090c9d55a5d0372b0eaf55ed711d4edf",
        "urn:uuid:1b35d0a5-b17a-423b-a2ed-de2b18dc367a": "7f5cc18f0b04e812a3b4c8f686ce34e6fec558804bf61e54b176742a7f6368d6",
    }
    return pids


@pytest.fixture
def store(tmp_path):
    d = tmp_path / "metacat"
    d.mkdir()
    store = HashStore(store_path=d.as_posix())
    return store


def hash_blob_string(data):
    """Calculate the SHA-256 digest for a blob, and return it in a base64 hex encoded string"""
    hex = hashlib.sha256(data).hexdigest()
    return hex


def test_pids_length(pids):
    assert len(pids) == 3


def test_init(store):
    value = store.version()
    assert value == importlib.metadata.version("hashstore")


def test_store_files(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        sysmeta = syspath.read_bytes()
        s_cid = store.store(pid, sysmeta, path)
        assert s_cid == pids[pid]
    assert store.objects.count() == 3


def test_add_files(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        cid = store._add_object(path)
        assert len(cid) == 64
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        sysmeta = syspath.read_bytes()
        s_cid = store._set_sysmeta(pid, sysmeta, cid)
        assert s_cid == pids[pid]
    assert store.objects.count() == 3


def test_hash_string(pids, store):
    for pid in pids:
        hash_val = store._hash_string(pid)
        assert hash_val == pids[pid]


def test_rel_path(pids, store):
    path = store._rel_path(pids["doi:10.18739/A2901ZH2M"])
    print(path)
    assert len(path) == 67
    assert path.startswith("0d/55/5e/d7")
    assert path.endswith("7052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e")


def test_retrieve_sysmeta(store):
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    filename = pid + ".xml"
    syspath = Path(test_dir) / filename
    sysmeta = syspath.read_bytes()
    store.store(pid, sysmeta, path)
    sysmeta_ret = store.retrieve_sysmeta(pid)
    assert sysmeta.decode("utf-8") == sysmeta_ret


def test_sysmeta_cid(store):
    test_dir = "tests/testdata/"
    obj_cid = "94f9b6c88f1f458e410c30c351c6384ea42ac1b5ee1f8430d3e365e43b78a38a"
    pid = "jtao.1700.1"
    path = test_dir + pid
    filename = pid + ".xml"
    syspath = Path(test_dir) / filename
    sysmeta = syspath.read_bytes()
    store.store(pid, sysmeta, path)
    s_content = store._get_sysmeta(pid)
    cid = s_content[0][:64]
    assert cid == obj_cid


def test_retrieve(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        sysmeta = syspath.read_bytes()
        store.store(pid, sysmeta, path)
        s_content = store._get_sysmeta(pid)
        cid = s_content[0][:64]
        cid_stream = store.retrieve(pid)[1]
        cid_content = cid_stream.read()
        cid_stream.close()
        cid_hash = hash_blob_string(cid_content)
        assert cid == cid_hash
