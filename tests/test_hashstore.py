from io import StringIO
from hashstore import ObjectStore


def test_init():
    store = ObjectStore(store_path="/tmp/metacat")
    value = store.version()
    assert value == "0.2.0"


def test_add_files():
    store = ObjectStore(store_path="/tmp/metacat")
    test_dir = "/var/metacat/documents/"
    pids = [
        "doi:10.18739_A2901ZH2M",
        "jtao.1700.1",
        "urn:uuid:1b35d0a5-b17a-423b-a2ed-de2b18dc367a",
    ]
    for pid in pids:
        path = test_dir + pid.replace("/", "_")
        cid = store.add_object(path)
        assert len(cid) == 64
        pid_object = StringIO(pid)
        s_cid = store.add_sysmeta(pid_object)
    assert store.count() == 3


def test_hash_string():
    store = ObjectStore(store_path="/tmp/metacat")
    pids = {
        "doi:10.18739_A2901ZH2M": "f6fac7b713ca66b61ff1c3c8259a8b98f6ceab30b906e42a24fa447db66fa8ba",
        "jtao.1700.1": "a8241925740d5dcd719596639e780e0a090c9d55a5d0372b0eaf55ed711d4edf",
        "urn:uuid:1b35d0a5-b17a-423b-a2ed-de2b18dc367a": "7f5cc18f0b04e812a3b4c8f686ce34e6fec558804bf61e54b176742a7f6368d6",
    }
    for pid in pids:
        hash_val = store.hash_string(pid)
        assert hash_val == pids[pid]


def test_path():
    pids = {
        "doi:10.18739_A2901ZH2M": "f6fac7b713ca66b61ff1c3c8259a8b98f6ceab30b906e42a24fa447db66fa8ba",
        "jtao.1700.1": "a8241925740d5dcd719596639e780e0a090c9d55a5d0372b0eaf55ed711d4edf",
        "urn:uuid:1b35d0a5-b17a-423b-a2ed-de2b18dc367a": "7f5cc18f0b04e812a3b4c8f686ce34e6fec558804bf61e54b176742a7f6368d6",
    }
    store = ObjectStore(store_path="/tmp/metacat")
    path = store.rel_path(pids["doi:10.18739_A2901ZH2M"])
    assert len(path) == 67
    assert path.startswith("f6/fa/c7/b7")
    assert path.endswith("13ca66b61ff1c3c8259a8b98f6ceab30b906e42a24fa447db66fa8ba")
    assert store.abs_path(pids["doi:10.18739_A2901ZH2M"]).endswith(path)
