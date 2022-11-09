from io import StringIO
from hashstore import ObjectStore

def test_init():
    store = ObjectStore(store_path='/tmp/metacat')
    value = store.version()
    assert value == '0.2.0'

def test_add_files():
    store = ObjectStore(store_path='/tmp/metacat')
    test_dir='/var/metacat/documents/'
    pids = ["doi:10.18739_A2901ZH2M", "jtao.1700.1", "urn:uuid:1b35d0a5-b17a-423b-a2ed-de2b18dc367a"]
    for pid in pids:
        path = test_dir+pid.replace('/', '_')
        cid = store.add_object(path)
        assert len(cid) == 64
        pid_object = StringIO(pid)
        s_cid = store.add_sysmeta(pid_object)
    assert store.count() == 3

def test_get_path():
    store = ObjectStore(store_path='/tmp/metacat')
    path = store.get_path('25c319f75e3fbed5a9f0497750ea12992b30d565')
    assert len(path)==43
    assert path.startswith('25/c3/19/f')
    assert path.endswith('f75e3fbed5a9f0497750ea12992b30d565')
