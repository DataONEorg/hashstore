import hashstore

def test_hello():
    assert 2+3==5
    value = hashstore.hello()
    assert value == 'Hello!'
