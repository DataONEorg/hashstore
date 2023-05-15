"""Test module for HashStore"""
import io
import importlib.metadata
from pathlib import Path
from threading import Thread
import pytest
from hashstore import HashStore


@pytest.fixture(name="pids")
def init_pids():
    """Generate test harness data"""
    test_pids = {
        "doi:10.18739/A2901ZH2M": {
            "ab_id": "0d555ed77052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e",
            "md5": "db91c910a3202478c8def1071c54aae5",
            "sha1": "1fe86e3c8043afa4c70857ca983d740ad8501ccd",
            "sha224": "922b1e86f83d3ea3060fd0f7b2cf04476e8b3ddeaa3cf48c2c3cf502",
            "sha256": "4d198171eef969d553d4c9537b1811a7b078f9a3804fc978a761bc014c05972c",
            "sha384": "d5953bd802fa74edea72eb941ead7a27639e62792fedc065d6c81de6c613b5b8739ab1f90e7f24a7500d154a727ed7c2",
            "sha512": "e9bcd6b91b102ef5803d1bd60c7a5d2dbec1a2baf5f62f7da60de07607ad6797d6a9b740d97a257fd2774f2c26503d455d8f2a03a128773477dfa96ab96a2e54",
        },
        "jtao.1700.1": {
            "ab_id": "a8241925740d5dcd719596639e780e0a090c9d55a5d0372b0eaf55ed711d4edf",
            "md5": "f4ea2d07db950873462a064937197b0f",
            "sha1": "3d25436c4490b08a2646e283dada5c60e5c0539d",
            "sha224": "9b3a96f434f3c894359193a63437ef86fbd5a1a1a6cc37f1d5013ac1",
            "sha256": "94f9b6c88f1f458e410c30c351c6384ea42ac1b5ee1f8430d3e365e43b78a38a",
            "sha384": "a204678330fcdc04980c9327d4e5daf01ab7541e8a351d49a7e9c5005439dce749ada39c4c35f573dd7d307cca11bea8",
            "sha512": "bf9e7f4d4e66bd082817d87659d1d57c2220c376cd032ed97cadd481cf40d78dd479cbed14d34d98bae8cebc603b40c633d088751f07155a94468aa59e2ad109",
        },
        "urn:uuid:1b35d0a5-b17a-423b-a2ed-de2b18dc367a": {
            "ab_id": "7f5cc18f0b04e812a3b4c8f686ce34e6fec558804bf61e54b176742a7f6368d6",
            "md5": "e1932fc75ca94de8b64f1d73dc898079",
            "sha1": "c6d2a69a3f5adaf478ba796c114f57b990cf7ad1",
            "sha224": "f86491d23d25dbaf7620542f056aba8a092a70be625502a6afd1fde0",
            "sha256": "4473516a592209cbcd3a7ba4edeebbdb374ee8e4a49d19896fafb8f278dc25fa",
            "sha384": "b1023a9be5aa23a102be9bce66e71f1f1c7a6b6b03e3fc603e9cd36b4265671e94f9cc5ce3786879740536994489bc26",
            "sha512": "c7fac7e8aacde8546ddb44c640ad127df82830bba6794aea9952f737c13a81d69095865ab3018ed2a807bf9222f80657faf31cfde6c853d7b91e617e148fec76",
        },
    }
    return test_pids


@pytest.fixture(name="store")
def init_store(tmp_path):
    """Create store path for all tests"""
    directory = tmp_path / "metacat"
    directory.mkdir()
    store = HashStore(store_path=directory.as_posix())
    return store


def test_pids_length(pids):
    """Ensure test harness pids are present"""
    assert len(pids) == 3


def test_init(store):
    """Check Hashstore initialization"""
    value = store.version()
    assert value == importlib.metadata.version("hashstore")


def test_store_address_length(pids, store):
    """Test store object ab_id length"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hash_address = store.store_object(pid, path)
        ab_id = hash_address.id
        assert len(ab_id) == 64


def test_store_object_files_path(pids, store):
    """Test store object when given a path"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = Path(test_dir + pid.replace("/", "_"))
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        _hash_address = store.store_object(pid, path)
        ab_id = store.store_sysmeta(pid, syspath)
        assert store.objects.exists(ab_id)
    assert store.objects.count() == 3


def test_store_object_files_string(pids, store):
    """Test store object when given a string"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path_string = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        _hash_address = store.store_object(pid, path_string)
        ab_id = store.store_sysmeta(pid, syspath)
        assert store.objects.exists(ab_id)
    assert store.objects.count() == 3


def test_store_object_files_input_stream(pids, store):
    """Test store object given an input stream"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        _hash_address = store.store_object(pid, input_stream)
        input_stream.close()
        ab_id = store.objects.get_sha256_hex_digest(pid)
        assert store.objects.exists(ab_id)
    assert store.objects.count() == 3


def test_store_object_id(pids, store):
    """Test store object returns expected id (ab_id)"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hash_address = store.store_object(pid, path)
        assert hash_address.id == pids[pid]["ab_id"]


def test_store_object_rel_path(pids, store):
    """Test store object returns expected relative path"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hash_address = store.store_object(pid, path)
        ab_id = pids[pid]["ab_id"]
        ab_id_rel_path = "/".join(store.objects.shard(ab_id))
        assert hash_address.relpath == ab_id_rel_path


def test_store_object_abs_path(pids, store):
    """Test store object returns expected absolute path"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hash_address = store.store_object(pid, path)
        ab_id = pids[pid]["ab_id"]
        ab_id_rel_path = "/".join(store.objects.shard(ab_id))
        ab_id_abs_path = store.objects.root + "/" + ab_id_rel_path
        assert hash_address.abspath == ab_id_abs_path


def test_store_object_is_duplicate(pids, store):
    """Test store object returns expected is_duplicate boolean"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hash_address = store.store_object(pid, path)
        assert hash_address.is_duplicate is False


def test_store_object_hex_digests(pids, store):
    """Test store object returns expected hex digests dictionary"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hash_address = store.store_object(pid, path)
        assert hash_address.hex_digests.get("md5") == pids[pid]["md5"]
        assert hash_address.hex_digests.get("sha1") == pids[pid]["sha1"]
        assert hash_address.hex_digests.get("sha256") == pids[pid]["sha256"]
        assert hash_address.hex_digests.get("sha384") == pids[pid]["sha384"]
        assert hash_address.hex_digests.get("sha512") == pids[pid]["sha512"]


def test_store_object_pid_empty(store):
    """Test store object raises error when supplied with empty pid string"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    with pytest.raises(ValueError):
        store.store_object("", path)


def test_store_object_pid_empty_spaces(store):
    """Test store object raises error when supplied with empty space character"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    with pytest.raises(ValueError):
        store.store_object(" ", path)


def test_store_object_pid_none(store):
    """Test store object raises error when supplied with None pid"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    with pytest.raises(ValueError):
        store.store_object(None, path)


def test_store_object_data_incorrect_type_none(store):
    """Test store object raises error when data is None"""
    pid = "jtao.1700.1"
    path = None
    with pytest.raises(TypeError):
        store.store_object(pid, path)


def test_store_object_data_incorrect_type_empty(store):
    """Test store object raises error when data is an empty string"""
    pid = "jtao.1700.1"
    path = ""
    with pytest.raises(TypeError):
        store.store_object(pid, path)


def test_store_object_data_incorrect_type_empty_spaces(store):
    """Test store object raises error when data is an empty string with spaces"""
    pid = "jtao.1700.1"
    path = "   "
    with pytest.raises(TypeError):
        store.store_object(pid, path)


def test_store_object_additional_algorithm_invalid(store):
    """Test store object raises error when supplied with unsupported algorithm"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_not_in_list = "abc"
    with pytest.raises(ValueError, match="Algorithm not supported"):
        store.store_object(pid, path, algorithm_not_in_list)


def test_store_object_additional_algorithm_hyphen_uppercase(pids, store):
    """Test store object formats algorithm in uppercase"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_with_hyphen_and_upper = "SHA-384"
    hash_address = store.store_object(pid, path, algorithm_with_hyphen_and_upper)
    sha256_cid = hash_address.hex_digests.get("sha384")
    assert sha256_cid == pids[pid]["sha384"]
    ab_id = store.objects.get_sha256_hex_digest(pid)
    assert store.objects.exists(ab_id)


def test_store_object_additional_algorithm_hyphen_lowercase(store):
    """Test store object with additional algorithm in lowercase"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_other = "sha3-256"
    hash_address = store.store_object(pid, path, algorithm_other)
    additional_sha3_256_hex_digest = hash_address.hex_digests.get("sha3_256")
    sha3_256_checksum = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    assert additional_sha3_256_hex_digest == sha3_256_checksum
    ab_id = store.objects.get_sha256_hex_digest(pid)
    assert store.objects.exists(ab_id)


def test_store_object_additional_algorithm_underscore(store):
    """Test store object with additional algorithm with underscore"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_other = "sha3_256"
    hash_address = store.store_object(pid, path, algorithm_other)
    additional_sha3_256_hex_digest = hash_address.hex_digests.get("sha3_256")
    sha3_256_checksum = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    assert additional_sha3_256_hex_digest == sha3_256_checksum
    pid_hash = store.objects.get_sha256_hex_digest(pid)
    assert store.objects.exists(pid_hash)


def test_store_object_checksum_correct(store):
    """Test store object successfully stores with good checksum"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_other = "sha3_256"
    checksum_correct = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    _hash_address = store.store_object(
        pid, path, checksum=checksum_correct, checksum_algorithm=algorithm_other
    )
    assert store.objects.count() == 1


def test_store_object_checksum_algorithm_empty(store):
    """Test store object raises error when checksum supplied with no checksum_algorithm"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    checksum_correct = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    with pytest.raises(ValueError):
        store.store_object(pid, path, checksum=checksum_correct, checksum_algorithm="")


def test_store_object_checksum_empty(store):
    """Test store object raises error when checksum_algorithm supplied and checksum is empty"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    checksum_algorithm = "sha3_256"
    with pytest.raises(ValueError):
        store.store_object(
            pid, path, checksum="", checksum_algorithm=checksum_algorithm
        )


def test_store_object_checksum_empty_spaces(store):
    """Test store object raises error when checksum_algorithm supplied and checksum is empty with spaces"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    checksum_algorithm = "sha3_256"
    with pytest.raises(ValueError):
        store.store_object(
            pid, path, checksum="  ", checksum_algorithm=checksum_algorithm
        )


def test_store_object_checksum_algorithm_empty_spaces(store):
    """Test store object raises error when checksum supplied with no checksum_algorithm"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    checksum_correct = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    with pytest.raises(ValueError):
        store.store_object(
            pid, path, checksum=checksum_correct, checksum_algorithm="   "
        )


def test_store_object_checksum_incorrect_checksum(store):
    """Test store object raises error when supplied with bad checksum"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_other = "sha3_256"
    checksum_incorrect = (
        "bbbb069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    with pytest.raises(ValueError):
        store.store_object(
            pid, path, checksum=algorithm_other, checksum_algorithm=checksum_incorrect
        )


def test_store_object_duplicate_raises_error(store):
    """Test store duplicate object throws FileExistsError"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    # Store first blob
    _hash_address_one = store.store_object(pid, path)
    # Store second blob
    with pytest.raises(FileExistsError):
        _hash_address_two = store.store_object(pid, path)
    assert store.objects.count() == 1
    ab_id = store.objects.get_sha256_hex_digest(pid)
    assert store.objects.exists(ab_id)


def test_store_object_duplicates_threads(store):
    """Test store object thread lock"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid

    file_exists_error_flag = False

    def store_object_wrapper(pid, path):
        nonlocal file_exists_error_flag
        try:
            store.store_object(pid, path)  # Call store_object inside the thread
        except FileExistsError:
            file_exists_error_flag = True

    thread1 = Thread(target=store_object_wrapper, args=(pid, path))
    thread2 = Thread(target=store_object_wrapper, args=(pid, path))
    thread3 = Thread(target=store_object_wrapper, args=(pid, path))
    thread1.start()
    thread2.start()
    thread3.start()
    thread1.join()
    thread2.join()
    thread3.join()
    # One thread will succeed, file count must still be 1
    assert store.objects.count() == 1
    ab_id = store.objects.get_sha256_hex_digest(pid)
    assert store.objects.exists(ab_id)
    assert file_exists_error_flag


def test_store_sysmeta_files_path(pids, store):
    """Test store sysmeta with path"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        _hash_address = store.store_object(pid, path)
        ab_id = store.store_sysmeta(pid, syspath)
        assert store.sysmeta.exists(ab_id)
    assert store.sysmeta.count() == 3


def test_store_sysmeta_files_string(pids, store):
    """Test store sysmeta with string"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path_string = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath_string = str(Path(test_dir) / filename)
        _hash_address = store.store_object(pid, path_string)
        ab_id = store.store_sysmeta(pid, syspath_string)
        assert store.sysmeta.exists(ab_id)
    assert store.sysmeta.count() == 3


def test_store_sysmeta_files_input_stream(pids, store):
    """Test store sysmeta with an input stream to sysmeta"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        _hash_address = store.store_object(pid, path)
        filename = pid.replace("/", "_") + ".xml"
        syspath_string = str(Path(test_dir) / filename)
        syspath_stream = io.open(syspath_string, "rb")
        _ab_id = store.store_sysmeta(pid, syspath_stream)
        syspath_stream.close()
    assert store.sysmeta.count() == 3


def test_store_sysmeta_pid_empty(store):
    """Test store sysmeta raises error with empty string"""
    test_dir = "tests/testdata/"
    pid = ""
    filename = pid.replace("/", "_") + ".xml"
    syspath_string = str(Path(test_dir) / filename)
    with pytest.raises(ValueError):
        store.store_sysmeta(pid, syspath_string)


def test_store_sysmeta_pid_empty_spaces(store):
    """Test store sysmeta raises error with empty string"""
    test_dir = "tests/testdata/"
    pid = "   "
    filename = pid.replace("/", "_") + ".xml"
    syspath_string = str(Path(test_dir) / filename)
    with pytest.raises(ValueError):
        store.store_sysmeta(pid, syspath_string)


def test_store_sysmeta_sysmeta_empty(store):
    """Test store sysmeta raises error with empty sysmeta string"""
    pid = "jtao.1700.1"
    syspath_string = "   "
    with pytest.raises(TypeError):
        store.store_sysmeta(pid, syspath_string)


def test_store_sysmeta_sysmeta_none(store):
    """Test store sysmeta raises error with empty sysmeta string"""
    pid = "jtao.1700.1"
    syspath_string = None
    with pytest.raises(TypeError):
        store.store_sysmeta(pid, syspath_string)


def test_store_sysmeta_ab_id(pids, store):
    """Test store sysmeta returns expected ab_id"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        _hash_address = store.store_object(pid, path)
        ab_id = store.store_sysmeta(pid, syspath)
        assert ab_id == pids[pid]["ab_id"]


def test_store_sysmeta_thread_lock(store):
    """Test store sysmeta thread lock"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    filename = pid + ".xml"
    syspath = Path(test_dir) / filename
    _hash_address = store.store_object(pid, path)
    store.store_sysmeta(pid, syspath)
    # Start threads
    thread1 = Thread(target=store.store_sysmeta, args=(pid, syspath))
    thread2 = Thread(target=store.store_sysmeta, args=(pid, syspath))
    thread3 = Thread(target=store.store_sysmeta, args=(pid, syspath))
    thread4 = Thread(target=store.store_sysmeta, args=(pid, syspath))
    thread1.start()
    thread2.start()
    thread3.start()
    thread4.start()
    thread1.join()
    thread2.join()
    thread3.join()
    thread4.join()
    assert store.sysmeta.count() == 1


def test_retrieve_object(pids, store):
    """Test retrieve_object returns correct object data"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        hash_address = store.store_object(pid, path)
        store.store_sysmeta(pid, syspath)
        obj_stream = store.retrieve_object(pid)
        sha256_hex = store.objects.computehash(obj_stream)
        obj_stream.close()
        assert sha256_hex == hash_address.hex_digests.get("sha256")


def test_retrieve_object_pid_empty(store):
    """Test retrieve_object raises error when supplied with empty pid"""
    pid = "   "
    with pytest.raises(ValueError):
        store.retrieve_object(pid)


def test_retrieve_object_pid_invalid(store):
    """Test retrieve_object raises error when supplied with bad pid"""
    pid = "jtao.1700.1"
    pid_does_not_exist = pid + "test"
    with pytest.raises(ValueError):
        store.retrieve_object(pid_does_not_exist)


def test_retrieve_sysmeta(store):
    """Test retrieve_sysmeta returns correct sysmeta data"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    filename = pid + ".xml"
    syspath = Path(test_dir) / filename
    _hash_address = store.store_object(pid, path)
    _ab_id = store.store_sysmeta(pid, syspath)
    sysmeta_ret = store.retrieve_sysmeta(pid)
    sysmeta = syspath.read_bytes()
    assert sysmeta.decode("utf-8") == sysmeta_ret


def test_retrieve_sysmeta_pid_invalid(store):
    """Test retrieve_sysmeta raises error when supplied with bad pid"""
    pid = "jtao.1700.1"
    pid_does_not_exist = pid + "test"
    with pytest.raises(ValueError):
        store.retrieve_sysmeta(pid_does_not_exist)


def test_retrieve_sysmeta_pid_empty(store):
    """Test retrieve_sysmeta raises error when supplied with empty pid"""
    pid = "    "
    with pytest.raises(ValueError):
        store.retrieve_sysmeta(pid)


def test_delete_objects(pids, store):
    """Test delete_object successfully deletes objects"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        _hash_address = store.store_object(pid, path)
        _ab_id = store.store_sysmeta(pid, syspath)
        store.delete_object(pid)
    assert store.objects.count() == 0


def test_delete_object_pid_empty(store):
    """Test delete_object raises error when empty pid supplied"""
    pid = "    "
    with pytest.raises(ValueError):
        store.delete_object(pid)


def test_delete_object_pid_none(store):
    """Test delete_object raises error when pid is none"""
    pid = None
    with pytest.raises(ValueError):
        store.delete_object(pid)


def test_delete_sysmeta(pids, store):
    """Test delete_sysmeta successfully deletes sysmeta"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        _hash_address = store.store_object(pid, path)
        _ab_id = store.store_sysmeta(pid, syspath)
        store.delete_sysmeta(pid)
    assert store.sysmeta.count() == 0


def test_delete_sysmeta_pid_empty(store):
    """Test delete_object raises error when empty pid supplied"""
    pid = "    "
    with pytest.raises(ValueError):
        store.delete_sysmeta(pid)


def test_delete_sysmeta_pid_none(store):
    """Test delete_object raises error when pid is none"""
    pid = None
    with pytest.raises(ValueError):
        store.delete_sysmeta(pid)


def test_get_hex_digest(store):
    """Test get_hex_digest for expected value"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    filename = pid + ".xml"
    syspath = Path(test_dir) / filename
    _hash_address = store.store_object(pid, path)
    _ab_id = store.store_sysmeta(pid, syspath)
    sha3_256_hex_digest = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    sha3_256_get = store.get_hex_digest(pid, "sha3_256")
    assert sha3_256_hex_digest == sha3_256_get


def test_get_hex_digest_pid_not_found(store):
    """Test get_hex_digest raises error when supplied with bad pid"""
    pid = "jtao.1700.1"
    pid_does_not_exist = pid + "test"
    algorithm = "sha256"
    with pytest.raises(ValueError):
        store.get_hex_digest(pid_does_not_exist, algorithm)


def test_get_hex_digest_pid_unsupported_algorithm(store):
    """Test get_hex_digest raises error when supplied with unsupported algorithm"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    filename = pid + ".xml"
    syspath = Path(test_dir) / filename
    syspath.read_bytes()
    _hash_address = store.store_object(pid, path)
    algorithm = "sm3"
    with pytest.raises(ValueError):
        store.get_hex_digest(pid, algorithm)


def test_get_hex_digest_pid_empty(store):
    """Test get_hex_digest raises error when supplied pid is empty"""
    pid = "    "
    algorithm = "sm3"
    with pytest.raises(ValueError):
        store.get_hex_digest(pid, algorithm)


def test_get_hex_digest_pid_none(store):
    """Test get_hex_digest raises error when supplied pid is None"""
    pid = None
    algorithm = "sm3"
    with pytest.raises(ValueError):
        store.get_hex_digest(pid, algorithm)


def test_get_hex_digest_algorithm_empty(store):
    """Test get_hex_digest raises error when supplied algorithm is empty"""
    pid = "jtao.1700.1"
    algorithm = "     "
    with pytest.raises(ValueError):
        store.get_hex_digest(pid, algorithm)


def test_get_hex_digest_algorithm_none(store):
    """Test get_hex_digest raises error when supplied algorithm is None"""
    pid = "jtao.1700.1"
    algorithm = None
    with pytest.raises(ValueError):
        store.get_hex_digest(pid, algorithm)
