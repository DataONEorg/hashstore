from hashstore import HashStore
from pathlib import Path
from threading import Thread
import io
import os
import importlib.metadata
import pytest


@pytest.fixture
def pids():
    pids = {
        "doi:10.18739/A2901ZH2M": {
            "s_cid": "0d555ed77052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e",
            "md5": "db91c910a3202478c8def1071c54aae5",
            "sha1": "1fe86e3c8043afa4c70857ca983d740ad8501ccd",
            "sha224": "922b1e86f83d3ea3060fd0f7b2cf04476e8b3ddeaa3cf48c2c3cf502",
            "sha256": "4d198171eef969d553d4c9537b1811a7b078f9a3804fc978a761bc014c05972c",
            "sha384": "d5953bd802fa74edea72eb941ead7a27639e62792fedc065d6c81de6c613b5b8739ab1f90e7f24a7500d154a727ed7c2",
            "sha512": "e9bcd6b91b102ef5803d1bd60c7a5d2dbec1a2baf5f62f7da60de07607ad6797d6a9b740d97a257fd2774f2c26503d455d8f2a03a128773477dfa96ab96a2e54",
        },
        "jtao.1700.1": {
            "s_cid": "a8241925740d5dcd719596639e780e0a090c9d55a5d0372b0eaf55ed711d4edf",
            "md5": "f4ea2d07db950873462a064937197b0f",
            "sha1": "3d25436c4490b08a2646e283dada5c60e5c0539d",
            "sha224": "9b3a96f434f3c894359193a63437ef86fbd5a1a1a6cc37f1d5013ac1",
            "sha256": "94f9b6c88f1f458e410c30c351c6384ea42ac1b5ee1f8430d3e365e43b78a38a",
            "sha384": "a204678330fcdc04980c9327d4e5daf01ab7541e8a351d49a7e9c5005439dce749ada39c4c35f573dd7d307cca11bea8",
            "sha512": "bf9e7f4d4e66bd082817d87659d1d57c2220c376cd032ed97cadd481cf40d78dd479cbed14d34d98bae8cebc603b40c633d088751f07155a94468aa59e2ad109",
        },
        "urn:uuid:1b35d0a5-b17a-423b-a2ed-de2b18dc367a": {
            "s_cid": "7f5cc18f0b04e812a3b4c8f686ce34e6fec558804bf61e54b176742a7f6368d6",
            "md5": "e1932fc75ca94de8b64f1d73dc898079",
            "sha1": "c6d2a69a3f5adaf478ba796c114f57b990cf7ad1",
            "sha224": "f86491d23d25dbaf7620542f056aba8a092a70be625502a6afd1fde0",
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
        hex_digest_dict = store.store_object(path)
        cid = hex_digest_dict.get("sha256")
        s_cid = store.store_sysmeta(pid, sysmeta, cid)
    assert store.objects.count() == 3
    assert store.sysmeta.count() == 3


def test_store_address_length(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hex_digest_dict = store.store_object(path)
        cid = hex_digest_dict.get("sha256")
        assert len(cid) == 64


def test_store_hex_digests(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hex_digest_dict = store.store_object(path)
        assert hex_digest_dict.get("md5") == pids[pid]["md5"]
        assert hex_digest_dict.get("sha1") == pids[pid]["sha1"]
        assert hex_digest_dict.get("sha256") == pids[pid]["sha256"]
        assert hex_digest_dict.get("sha384") == pids[pid]["sha384"]
        assert hex_digest_dict.get("sha512") == pids[pid]["sha512"]


def test_store_input_stream(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        hex_digest_dict = store.store_object(input_stream)
        assert hex_digest_dict.get("md5") == pids[pid]["md5"]
        assert hex_digest_dict.get("sha1") == pids[pid]["sha1"]
        assert hex_digest_dict.get("sha256") == pids[pid]["sha256"]
        assert hex_digest_dict.get("sha384") == pids[pid]["sha384"]
        assert hex_digest_dict.get("sha512") == pids[pid]["sha512"]
        input_stream.close()
    return


def test_store_object_algorithm_args_invalid(store):
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_not_in_list = "abc"
    with pytest.raises(ValueError, match="Algorithm not supported"):
        store.store_object(path, algorithm_not_in_list)


def test_store_object_algorithm_args_hyphen(pids, store):
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_with_hyphen_and_upper = "SHA-256"
    hex_digest_dict = store.store_object(path, algorithm_with_hyphen_and_upper)
    cid = hex_digest_dict.get("sha256")
    assert cid == pids[pid]["sha256"]


def test_store_object_algorithm_args_other(store):
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_other = "sha3_256"
    hex_digest_dict = store.store_object(path, algorithm_other)
    cid = hex_digest_dict.get("sha3_256")
    sha3_256_checksum = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    assert cid == sha3_256_checksum


def test_store_object_algorithm_args_other_hyphen(store):
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_other = "sha3-256"
    hex_digest_dict = store.store_object(path, algorithm_other)
    cid = hex_digest_dict.get("sha3_256")
    sha3_256_checksum = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    assert cid == sha3_256_checksum


def test_store_object_algorithm_args_incorrect_checksum(store):
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_other = "sha3_256"
    checksum_incorrect = (
        "bbbb069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    with pytest.raises(ValueError):
        store.store_object(path, algorithm_other, checksum_incorrect)
    assert store.objects.count() == 0


def test_store_duplicate_objects(store):
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    store.store_object(path)
    with pytest.raises(FileExistsError):
        store.store_object(path)
    assert store.objects.count() == 1


def test_store_duplicate_object_threads(store):
    # FileExistsError can potentially be raised as a warning (expected)
    # File count must be 1
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    thread1 = Thread(target=store.store_object, args=(path,))
    thread2 = Thread(target=store.store_object, args=(path,))
    thread3 = Thread(target=store.store_object, args=(path,))
    thread1.start()
    thread2.start()
    thread3.start()
    thread1.join()
    thread2.join()
    thread3.join()
    assert store.objects.count() == 1


def test_store_sysmeta_s_cid(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        sysmeta = syspath.read_bytes()
        hex_digest_dict = store.store_object(path)
        cid = hex_digest_dict.get("sha256")
        s_cid = store.store_sysmeta(pid, sysmeta, cid)
        assert s_cid == pids[pid]["s_cid"]


def test_store_sysmeta_cid(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        sysmeta = syspath.read_bytes()
        hex_digest_dict = store.store_object(path)
        cid = hex_digest_dict.get("sha256")
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
    hex_digest_dict = store.store_object(path)
    cid = hex_digest_dict.get("sha256")
    s_cid = store.store_sysmeta(pid, sysmeta, cid)
    cid_new = obj_cid[::-1]
    store.store_sysmeta(pid, sysmeta, cid_new)
    s_content = store._get_sysmeta(pid)
    cid_get = s_content[0][:64]
    assert cid_new == cid_get


def test_store_sysmeta_thread_lock(store):
    test_dir = "tests/testdata/"
    obj_cid = "94f9b6c88f1f458e410c30c351c6384ea42ac1b5ee1f8430d3e365e43b78a38a"
    pid = "jtao.1700.1"
    pid_two = pid + "2"
    path = test_dir + pid
    filename = pid + ".xml"
    syspath = Path(test_dir) / filename
    sysmeta = syspath.read_bytes()
    hex_digest_dict = store.store_object(path)
    cid = hex_digest_dict.get("sha256")
    store.store_sysmeta(pid, sysmeta, cid)
    test_cid = obj_cid[::-1]
    test_cid_two = "9999b6c88f1f458e410c30c351c6384ea42ac1b5ee1f8430d3e365e43b78a38a"
    # Start threads
    thread1 = Thread(target=store.store_sysmeta, args=(pid, sysmeta, cid))
    thread2 = Thread(target=store.store_sysmeta, args=(pid, sysmeta, test_cid))
    thread3 = Thread(target=store.store_sysmeta, args=(pid_two, sysmeta, cid))
    thread4 = Thread(target=store.store_sysmeta, args=(pid, sysmeta, test_cid_two))
    thread1.start()
    thread2.start()
    thread3.start()
    thread4.start()
    thread1.join()
    thread2.join()
    thread3.join()
    thread4.join()
    cid_check = store._get_sysmeta(pid)[0][:64]
    assert cid_check == test_cid or cid_check == test_cid_two
    assert store.objects.count() == 1
    assert store.sysmeta.count() == 2


def test_retrieve_object(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        sysmeta = syspath.read_bytes()
        hex_digest_dict = store.store_object(path)
        obj_cid = hex_digest_dict.get("sha256")
        store.store_sysmeta(pid, sysmeta, obj_cid)
        s_content = store._get_sysmeta(pid)
        cid = s_content[0][:64]
        cid_stream = store.retrieve_object(pid)[1]
        cid_hash = store.objects.computehash(cid_stream)
        cid_stream.close()
        assert cid == cid_hash


def test_retrieve_sysmeta(store):
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    filename = pid + ".xml"
    syspath = Path(test_dir) / filename
    sysmeta = syspath.read_bytes()
    hex_digest_dict = store.store_object(path)
    cid = hex_digest_dict.get("sha256")
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
        hex_digest_dict = store.store_object(path)
        cid = hex_digest_dict.get("sha256")
        s_cid = store.store_sysmeta(pid, sysmeta, cid)
        store.delete_object(pid)
        store.delete_sysmeta(pid)
    assert store.objects.count() == 0
    assert store.sysmeta.count() == 0


def test_get_hex_digest(store):
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    filename = pid + ".xml"
    syspath = Path(test_dir) / filename
    sysmeta = syspath.read_bytes()
    hex_digest_dict = store.store_object(path)
    cid = hex_digest_dict.get("sha256")
    s_cid = store.store_sysmeta(pid, sysmeta, cid)
    sha3_256_hex_digest = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    sha3_256_get = store.get_hex_digest(pid, "sha3_256")
    assert sha3_256_hex_digest == sha3_256_get


def test_get_hex_digest_pid_not_found(store):
    pid = "jtao.1700.1"
    pid_does_not_exist = pid + "test"
    algorithm = "sha256"
    with pytest.raises(ValueError):
        store.get_hex_digest(pid_does_not_exist, algorithm)


def test_get_hex_digest_pid_unsupported_algorithm(store):
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    filename = pid + ".xml"
    syspath = Path(test_dir) / filename
    syspath.read_bytes()
    store.store_object(path)
    algorithm = "sm3"
    with pytest.raises(ValueError):
        store.get_hex_digest(pid, algorithm)


def test_hash_string(pids, store):
    for pid in pids:
        hash_val = store._hash_string(pid)
        assert hash_val == pids[pid]["s_cid"]


def test_rel_path(pids, store):
    path = store._rel_path(pids["doi:10.18739/A2901ZH2M"]["s_cid"])
    assert len(path) == 67
    assert path.startswith("0d/55/5e/d7")
    assert path.endswith("7052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e")


def test_clean_algorithm(store):
    algorithm_underscore = "sha_256"
    algorithm_hyphen = "sha-256"
    algorithm_other_hyphen = "sha3-256"
    cleaned_algo_underscore = store._clean_algorithm(algorithm_underscore)
    cleaned_algo_hyphen = store._clean_algorithm(algorithm_hyphen)
    cleaned_algo_other_hyphen = store._clean_algorithm(algorithm_other_hyphen)
    assert cleaned_algo_underscore == "sha256"
    assert cleaned_algo_hyphen == "sha256"
    assert cleaned_algo_other_hyphen == "sha3_256"


def test_computehash(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        cid_stream = io.open(path, "rb")
        cid_hash = store.objects.computehash(cid_stream, "sha256")
        cid_stream.close()
        assert pids[pid]["sha256"] == cid_hash


def test_put(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        pid_hashaddress = store.objects.put(path)
        pid_id = pid_hashaddress.id
        pid_relpath = pid_hashaddress.relpath
        pid_abspath = pid_hashaddress.abspath
        pid_is_duplicate = pid_hashaddress.is_duplicate
        pid_hex_digests = pid_hashaddress.hex_digests
        assert pid_id == pids[pid]["sha256"]
        shard_id_path = "/".join(store.objects.shard(pid_id))
        assert pid_relpath == shard_id_path
        id_abs_path = store.objects.realpath(pid_id)
        assert pid_abspath == id_abs_path
        assert pid_is_duplicate is False
        assert pid_hex_digests.get("md5") == pids[pid]["md5"]
        assert pid_hex_digests.get("sha1") == pids[pid]["sha1"]
        assert pid_hex_digests.get("sha256") == pids[pid]["sha256"]
        assert pid_hex_digests.get("sha384") == pids[pid]["sha384"]
        assert pid_hex_digests.get("sha512") == pids[pid]["sha512"]


def test_put_additional_algorithm(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        algo = "sha224"
        path = test_dir + pid.replace("/", "_")
        pid_hashaddress = store.objects.put(path, algorithm=algo)
        pid_hex_digests = pid_hashaddress.hex_digests
        pid_sha224 = pid_hex_digests.get(algo)
        assert pid_sha224 == pids[pid][algo]


def test_put_with_correct_checksums(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        algo = "sha224"
        algo_checksum = pids[pid][algo]
        path = test_dir + pid.replace("/", "_")
        store.objects.put(path, algorithm=algo, checksum=algo_checksum)
    assert store.objects.count() == 3


def test_put_with_incorrect_checksum(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        algo = "sha224"
        algo_checksum = "badChecksumValue"
        path = test_dir + pid.replace("/", "_")
        with pytest.raises(ValueError):
            store.objects.put(path, algorithm=algo, checksum=algo_checksum)
    assert store.objects.count() == 0


def test_copy(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        hex_digests, file_path, is_duplicate = store.objects._copy(input_stream)
        assert hex_digests.get("md5") == pids[pid]["md5"]
        assert hex_digests.get("sha1") == pids[pid]["sha1"]
        assert hex_digests.get("sha256") == pids[pid]["sha256"]
        assert hex_digests.get("sha384") == pids[pid]["sha384"]
        assert hex_digests.get("sha512") == pids[pid]["sha512"]
        assert os.path.isfile(file_path) is True
        assert is_duplicate is False


def test_copy_duplicates(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        store.objects._copy(input_stream)
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        hex_digests, file_path, is_duplicate = store.objects._copy(input_stream)
        assert is_duplicate is True
        assert store.objects.count() == 3


def test_mktempfile(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        hex_digests, tmp_file_name = store.objects._mktempfile(input_stream)
        assert hex_digests.get("md5") == pids[pid]["md5"]
        assert hex_digests.get("sha1") == pids[pid]["sha1"]
        assert hex_digests.get("sha256") == pids[pid]["sha256"]
        assert hex_digests.get("sha384") == pids[pid]["sha384"]
        assert hex_digests.get("sha512") == pids[pid]["sha512"]
        assert os.path.isfile(tmp_file_name) is True


def test_mktempfile_with_algorithm(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        algo = "sha224"
        hex_digests, tmp_file_name = store.objects._mktempfile(input_stream, algo)
        assert hex_digests.get("sha224") == pids[pid]["sha224"]


def test_mktempfile_with_unsupported_algorithm(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        algo = "md2"
        with pytest.raises(ValueError):
            hex_digests, tmp_file_name = store.objects._mktempfile(input_stream, algo)


def test_to_bytes(store):
    string = "teststring"
    string_bytes = store.objects._to_bytes(string)
    assert isinstance(string_bytes, bytes)