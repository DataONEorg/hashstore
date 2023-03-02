from hashstore import HashStore
from pathlib import Path
import hashlib
import importlib.metadata
import pytest


@pytest.fixture
def pids():
    pids = {
        "doi:10.18739/A2901ZH2M": {
            "s_cid": "0d555ed77052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e",
            "md5": "db91c910a3202478c8def1071c54aae5",
            "sha1": "1fe86e3c8043afa4c70857ca983d740ad8501ccd",
            "sha256": "4d198171eef969d553d4c9537b1811a7b078f9a3804fc978a761bc014c05972c",
            "sha384": "d5953bd802fa74edea72eb941ead7a27639e62792fedc065d6c81de6c613b5b8739ab1f90e7f24a7500d154a727ed7c2",
            "sha512": "e9bcd6b91b102ef5803d1bd60c7a5d2dbec1a2baf5f62f7da60de07607ad6797d6a9b740d97a257fd2774f2c26503d455d8f2a03a128773477dfa96ab96a2e54",
        },
        "jtao.1700.1": {
            "s_cid": "a8241925740d5dcd719596639e780e0a090c9d55a5d0372b0eaf55ed711d4edf",
            "md5": "f4ea2d07db950873462a064937197b0f",
            "sha1": "3d25436c4490b08a2646e283dada5c60e5c0539d",
            "sha256": "94f9b6c88f1f458e410c30c351c6384ea42ac1b5ee1f8430d3e365e43b78a38a",
            "sha384": "a204678330fcdc04980c9327d4e5daf01ab7541e8a351d49a7e9c5005439dce749ada39c4c35f573dd7d307cca11bea8",
            "sha512": "bf9e7f4d4e66bd082817d87659d1d57c2220c376cd032ed97cadd481cf40d78dd479cbed14d34d98bae8cebc603b40c633d088751f07155a94468aa59e2ad109",
        },
        "urn:uuid:1b35d0a5-b17a-423b-a2ed-de2b18dc367a": {
            "s_cid": "7f5cc18f0b04e812a3b4c8f686ce34e6fec558804bf61e54b176742a7f6368d6",
            "md5": "e1932fc75ca94de8b64f1d73dc898079",
            "sha1": "c6d2a69a3f5adaf478ba796c114f57b990cf7ad1",
            "sha256": "4473516a592209cbcd3a7ba4edeebbdb374ee8e4a49d19896fafb8f278dc25fa",
            "sha384": "b1023a9be5aa23a102be9bce66e71f1f1c7a6b6b03e3fc603e9cd36b4265671e94f9cc5ce3786879740536994489bc26",
            "sha512": "c7fac7e8aacde8546ddb44c640ad127df82830bba6794aea9952f737c13a81d69095865ab3018ed2a807bf9222f80657faf31cfde6c853d7b91e617e148fec76",
        },
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
        checksums = store.store_object(path, "sha256")
        cid = checksums.get("sha256")
        s_cid = store.store_sysmeta(pid, sysmeta, cid)
    assert store.objects.count() == 3


def test_store_address_length(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        checksums = store.store_object(path, "sha256")
        cid = checksums.get("sha256")
        assert len(cid) == 64


def test_store_checksums(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        checksums = store.store_object(path, "sha256")
        assert checksums.get("md5") == pids[pid]["md5"]
        assert checksums.get("sha1") == pids[pid]["sha1"]
        assert checksums.get("sha256") == pids[pid]["sha256"]
        assert checksums.get("sha384") == pids[pid]["sha384"]
        assert checksums.get("sha512") == pids[pid]["sha512"]


def test_store_object_algorithm_args(pids, store):
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_not_in_list = "abc"
    with pytest.raises(ValueError, match="Algorithm not supported"):
        checksums = store.store_object(path, algorithm_not_in_list)
    algorithm_with_hyphen_and_upper = "SHA-256"
    checksums = store.store_object(path, algorithm_with_hyphen_and_upper)
    cid = checksums.get("sha256")
    assert cid == pids[pid]["sha256"]


def test_store_duplicate_objects(store):
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm = "sha256"
    store.store_object(path, algorithm)
    is_duplicate = store.store_object(path, algorithm)
    assert is_duplicate == None


def test_store_sysmeta_s_cid(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        sysmeta = syspath.read_bytes()
        checksums = store.store_object(path, "sha256")
        cid = checksums.get("sha256")
        s_cid = store.store_sysmeta(pid, sysmeta, cid)
        assert s_cid == pids[pid]["s_cid"]


def test_store_sysmeta_cid(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        sysmeta = syspath.read_bytes()
        checksums = store.store_object(path, "sha256")
        cid = checksums.get("sha256")
        store.store_sysmeta(pid, sysmeta, cid)
        s_content = store._get_sysmeta(pid)
        cid_get = s_content[0][:64]
        assert cid_get == pids[pid]["sha256"]


def test_store_sysmeta_update(store):
    test_dir = "tests/testdata/"
    obj_cid = "94f9b6c88f1f458e410c30c351c6384ea42ac1b5ee1f8430d3e365e43b78a38a"
    pid = "jtao.1700.1"
    path = test_dir + pid
    filename = pid + ".xml"
    syspath = Path(test_dir) / filename
    sysmeta = syspath.read_bytes()
    checksums = store.store_object(path, "sha256")
    cid = checksums.get("sha256")
    s_cid = store.store_sysmeta(pid, sysmeta, cid)
    cid_new = obj_cid[::-1]
    store.store_sysmeta(pid, sysmeta, cid_new)
    s_content = store._get_sysmeta(pid)
    cid_get = s_content[0][:64]
    assert cid_new == cid_get
    tmp_sysmeta = store.tmp.exists(s_cid)
    assert tmp_sysmeta == False
    sys_sysmeta = store.sysmeta.exists(s_cid)
    assert sys_sysmeta == True


def test_retrieve_object(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        sysmeta = syspath.read_bytes()
        checksums = store.store_object(path, "sha256")
        obj_cid = checksums.get("sha256")
        store.store_sysmeta(pid, sysmeta, obj_cid)
        s_content = store._get_sysmeta(pid)
        cid = s_content[0][:64]
        cid_stream = store.retrieve_object(pid)[1]
        cid_content = cid_stream.read()
        cid_stream.close()
        cid_hash = hash_blob_string(cid_content)
        assert cid == cid_hash


def test_retrieve_sysmeta(store):
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    filename = pid + ".xml"
    syspath = Path(test_dir) / filename
    sysmeta = syspath.read_bytes()
    checksums = store.store_object(path, "sha256")
    cid = checksums.get("sha256")
    s_cid = store.store_sysmeta(pid, sysmeta, cid)
    sysmeta_ret = store.retrieve_sysmeta(pid)
    assert sysmeta.decode("utf-8") == sysmeta_ret


def test_delete(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        sysmeta = syspath.read_bytes()
        checksums = store.store_object(path, "sha256")
        cid = checksums.get("sha256")
        s_cid = store.store_sysmeta(pid, sysmeta, cid)
        store.delete(pid)
    assert store.objects.count() == 0
    assert store.sysmeta.count() == 0


def test_hash_string(pids, store):
    for pid in pids:
        hash_val = store._hash_string(pid)
        assert hash_val == pids[pid]["s_cid"]


def test_rel_path(pids, store):
    path = store._rel_path(pids["doi:10.18739/A2901ZH2M"]["s_cid"])
    print(path)
    assert len(path) == 67
    assert path.startswith("0d/55/5e/d7")
    assert path.endswith("7052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e")
