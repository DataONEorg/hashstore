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


def test_computehash(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        obj_stream = io.open(path, "rb")
        obj_sha256_hash = store.objects.computehash(obj_stream, "sha256")
        obj_stream.close()
        assert pids[pid]["sha256"] == obj_sha256_hash


def test_put(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hashaddress = store.objects.put(pid, path)
        hashaddress_id = hashaddress.id
        hashaddress_relpath = hashaddress.relpath
        hashaddress_abspath = hashaddress.abspath
        hashaddress_is_duplicate = hashaddress.is_duplicate
        hashaddress_hex_digests = hashaddress.hex_digests
        assert hashaddress_id == pids[pid]["ab_id"]
        shard_id_path = "/".join(store.objects.shard(hashaddress_id))
        assert hashaddress_relpath == shard_id_path
        id_abs_path = store.objects.realpath(hashaddress_id)
        assert hashaddress_abspath == id_abs_path
        assert hashaddress_is_duplicate is False
        assert hashaddress_hex_digests.get("md5") == pids[pid]["md5"]
        assert hashaddress_hex_digests.get("sha1") == pids[pid]["sha1"]
        assert hashaddress_hex_digests.get("sha256") == pids[pid]["sha256"]
        assert hashaddress_hex_digests.get("sha384") == pids[pid]["sha384"]
        assert hashaddress_hex_digests.get("sha512") == pids[pid]["sha512"]


def test_put_additional_algorithm(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        algo = "sha224"
        path = test_dir + pid.replace("/", "_")
        hash_address = store.objects.put(pid, path, additional_algorithm=algo)
        hex_digests = hash_address.hex_digests
        sha224_hash = hex_digests.get(algo)
        assert sha224_hash == pids[pid][algo]


def test_put_with_correct_checksums(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        algo = "sha224"
        algo_checksum = pids[pid][algo]
        path = test_dir + pid.replace("/", "_")
        store.objects.put(pid, path, checksum=algo_checksum, checksum_algorithm=algo)
    assert store.objects.count() == 3


def test_put_with_incorrect_checksum(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        algo = "sha224"
        algo_checksum = "badChecksumValue"
        path = test_dir + pid.replace("/", "_")
        with pytest.raises(ValueError):
            store.objects.put(pid, path, checksum=algo_checksum, checksum_algorithm=algo)
    assert store.objects.count() == 0


def test_move_and_get_checksums(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        (
            id,
            hex_digests,
            file_path,
            is_duplicate,
        ) = store.objects._move_and_get_checksums(pid, input_stream)
        input_stream.close()
        ab_id = store.objects._get_sha256_hex_digest(pid)
        assert id == ab_id
        assert hex_digests.get("md5") == pids[pid]["md5"]
        assert hex_digests.get("sha1") == pids[pid]["sha1"]
        assert hex_digests.get("sha256") == pids[pid]["sha256"]
        assert hex_digests.get("sha384") == pids[pid]["sha384"]
        assert hex_digests.get("sha512") == pids[pid]["sha512"]
        assert os.path.isfile(file_path) is True
        assert is_duplicate is False


def test_move_and_get_checksums_duplicates(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        store.objects._move_and_get_checksums(pid, input_stream)
        input_stream.close()
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        (
            id,
            hex_digests,
            file_path,
            is_duplicate,
        ) = store.objects._move_and_get_checksums(pid, input_stream)
        input_stream.close()
        assert is_duplicate is True
        assert store.objects.count() == 3


def test_mktempfile(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        hex_digests, tmp_file_name = store.objects._mktempfile(input_stream)
        input_stream.close()
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
        input_stream.close()
        assert hex_digests.get("sha224") == pids[pid]["sha224"]


def test_mktempfile_with_unsupported_algorithm(pids, store):
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        algo = "md2"
        with pytest.raises(ValueError):
            hex_digests, tmp_file_name = store.objects._mktempfile(input_stream, algo)
        input_stream.close()


def test_to_bytes(store):
    string = "teststring"
    string_bytes = store.objects._to_bytes(string)
    assert isinstance(string_bytes, bytes)


def test_get_store_path(store):
    path_objects = store.objects._get_store_path()
    path_objects_string = str(path_objects)
    assert path_objects_string.endswith("/metacat/objects")
    path_sysmeta = store.sysmeta._get_store_path()
    path_sysmeta_string = str(path_sysmeta)
    assert path_sysmeta_string.endswith("/metacat/sysmeta")


def test_clean_algorithm(store):
    algorithm_underscore = "sha_256"
    algorithm_hyphen = "sha-256"
    algorithm_other_hyphen = "sha3-256"
    cleaned_algo_underscore = store.objects.clean_algorithm(algorithm_underscore)
    cleaned_algo_hyphen = store.objects.clean_algorithm(algorithm_hyphen)
    cleaned_algo_other_hyphen = store.objects.clean_algorithm(algorithm_other_hyphen)
    assert cleaned_algo_underscore == "sha256"
    assert cleaned_algo_hyphen == "sha256"
    assert cleaned_algo_other_hyphen == "sha3_256"