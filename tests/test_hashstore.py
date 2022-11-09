from hashstore import ObjectStore
from pathlib import Path
import importlib.metadata

def test_init():
    store = ObjectStore(store_path="/tmp/metacat")
    value = store.version()
    assert value == importlib.metadata.version('hashstore')


def test_add_files():
    store = ObjectStore(store_path="/tmp/metacat")
    test_dir = "/var/metacat"
    pids = [
        "doi:10.18739/A2901ZH2M",
        "jtao.1700.1",
        "urn:uuid:1b35d0a5-b17a-423b-a2ed-de2b18dc367a",
    ]
    for pid in pids:
        path = test_dir + '/documents/' + pid.replace("/", "_")
        cid = store.add_object(path)
        assert len(cid) == 64
        filename = pid.replace("/", "_") + '.xml'
        syspath = Path(test_dir) / 'sysmeta' / filename
        sysmeta = syspath.read_bytes()
        s_cid = store.add_sysmeta(pid, sysmeta)
    assert store.count() == 3


def test_hash_string():
    store = ObjectStore(store_path="/tmp/metacat")
    pids = {
        "doi:10.18739/A2901ZH2M": "0d555ed77052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e",
        "jtao.1700.1": "a8241925740d5dcd719596639e780e0a090c9d55a5d0372b0eaf55ed711d4edf",
        "urn:uuid:1b35d0a5-b17a-423b-a2ed-de2b18dc367a": "7f5cc18f0b04e812a3b4c8f686ce34e6fec558804bf61e54b176742a7f6368d6",
    }
    for pid in pids:
        hash_val = store.hash_string(pid)
        assert hash_val == pids[pid]


def test_path():
    pids = {
        "doi:10.18739/A2901ZH2M": "0d555ed77052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e",
        "jtao.1700.1": "a8241925740d5dcd719596639e780e0a090c9d55a5d0372b0eaf55ed711d4edf",
        "urn:uuid:1b35d0a5-b17a-423b-a2ed-de2b18dc367a": "7f5cc18f0b04e812a3b4c8f686ce34e6fec558804bf61e54b176742a7f6368d6",
    }
    store = ObjectStore(store_path="/tmp/metacat")
    path = store.rel_path(pids["doi:10.18739/A2901ZH2M"])
    assert len(path) == 67
    assert path.startswith("0d/55/5e/d7")
    assert path.endswith("7052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e")
    assert store.abs_path(pids["doi:10.18739/A2901ZH2M"]).endswith(path)
