import hashstore

def test_hello():
    store = hashstore.D1Store()
    value = store.version()
    assert value == '0.0.1'
    store.init()
    #assert fs.size() > 2
