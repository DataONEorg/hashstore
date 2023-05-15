"""Test module for HashFSExt"""
import io
import os
import importlib.metadata
from pathlib import Path
import pytest
from hashstore import HashStore


@pytest.fixture(name="pids")
def init_pids():
    """Generate test harness data"""
    test_harness = {
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
    return test_harness


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


def test_computehash(pids, store):
    """Test to check computehash method"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        obj_stream = io.open(path, "rb")
        obj_sha256_hash = store.objects.computehash(obj_stream, "sha256")
        obj_stream.close()
        assert pids[pid]["sha256"] == obj_sha256_hash


def test_put_files_path(pids, store):
    """Test put objects with path object"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hash_address = store.objects.put(pid, path)
        hashaddress_id = hash_address.id
        assert store.objects.exists(hashaddress_id)
    assert store.objects.count() == 3


def test_put_files_string(pids, store):
    """Test put objects with string"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path_string = test_dir + pid.replace("/", "_")
        hash_address = store.objects.put(pid, path_string)
        hashaddress_id = hash_address.id
        assert store.objects.exists(hashaddress_id)
    assert store.objects.count() == 3


def test_put_files_stream(pids, store):
    """Test put objects with stream"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        hash_address = store.store_object(pid, input_stream)
        input_stream.close()
        hashaddress_id = hash_address.id
        assert store.objects.exists(hashaddress_id)
    assert store.objects.count() == 3


def test_put_id(pids, store):
    """Check put returns correct id"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hashaddress = store.objects.put(pid, path)
        hashaddress_id = hashaddress.id
        assert hashaddress_id == pids[pid]["ab_id"]


def test_put_relpath(pids, store):
    """Check put returns correct relative path"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hashaddress = store.objects.put(pid, path)
        hashaddress_id = hashaddress.id
        hashaddress_relpath = hashaddress.relpath
        shard_id_path = "/".join(store.objects.shard(hashaddress_id))
        assert hashaddress_relpath == shard_id_path


def test_put_abspath(pids, store):
    """Check put returns correct absolute path"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hashaddress = store.objects.put(pid, path)
        hashaddress_id = hashaddress.id
        hashaddress_abspath = hashaddress.abspath
        id_abs_path = store.objects.realpath(hashaddress_id)
        assert hashaddress_abspath == id_abs_path


def test_put_is_duplicate(pids, store):
    """Check put returns expected is_duplicate boolean value"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hashaddress = store.objects.put(pid, path)
        hashaddress_is_duplicate = hashaddress.is_duplicate
        assert hashaddress_is_duplicate is False


def test_put_hex_digests(pids, store):
    """Check put successfully generates hex digests dictionary"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hashaddress = store.objects.put(pid, path)
        hashaddress_hex_digests = hashaddress.hex_digests
        assert hashaddress_hex_digests.get("md5") == pids[pid]["md5"]
        assert hashaddress_hex_digests.get("sha1") == pids[pid]["sha1"]
        assert hashaddress_hex_digests.get("sha256") == pids[pid]["sha256"]
        assert hashaddress_hex_digests.get("sha384") == pids[pid]["sha384"]
        assert hashaddress_hex_digests.get("sha512") == pids[pid]["sha512"]


def test_put_additional_algorithm(pids, store):
    """Check put returns additional algorithm in hex digests"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        algo = "sha224"
        path = test_dir + pid.replace("/", "_")
        hash_address = store.objects.put(pid, path, additional_algorithm=algo)
        hex_digests = hash_address.hex_digests
        sha224_hash = hex_digests.get(algo)
        assert sha224_hash == pids[pid][algo]


def test_put_with_correct_checksums(pids, store):
    """Check put succeeds when good checksum supplied"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        algo = "sha224"
        algo_checksum = pids[pid][algo]
        path = test_dir + pid.replace("/", "_")
        store.objects.put(pid, path, checksum=algo_checksum, checksum_algorithm=algo)
    assert store.objects.count() == 3


def test_put_with_incorrect_checksum(pids, store):
    """Check put fails when bad checksum supplied"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        algo = "sha224"
        algo_checksum = "badChecksumValue"
        path = test_dir + pid.replace("/", "_")
        with pytest.raises(ValueError):
            store.objects.put(
                pid, path, checksum=algo_checksum, checksum_algorithm=algo
            )
    assert store.objects.count() == 0


def test_move_and_get_checksums_id(pids, store):
    """Test move returns correct id"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        # pylint: disable=W0212
        (
            move_id,
            _,
            _,
            _,
            _,
        ) = store.objects._move_and_get_checksums(pid, input_stream)
        input_stream.close()
        ab_id = store.objects.get_sha256_hex_digest(pid)
        assert move_id == ab_id


def test_move_and_get_checksums_hex_digests(pids, store):
    """Test move returns correct hex digests"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        # pylint: disable=W0212
        (
            _,
            _,
            _,
            _,
            hex_digests,
        ) = store.objects._move_and_get_checksums(pid, input_stream)
        input_stream.close()
        assert hex_digests.get("md5") == pids[pid]["md5"]
        assert hex_digests.get("sha1") == pids[pid]["sha1"]
        assert hex_digests.get("sha256") == pids[pid]["sha256"]
        assert hex_digests.get("sha384") == pids[pid]["sha384"]
        assert hex_digests.get("sha512") == pids[pid]["sha512"]


def test_move_and_get_checksums_abs_path(pids, store):
    """Test move returns correct absolute path"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        # pylint: disable=W0212
        (
            _,
            _,
            abs_path,
            _,
            _,
        ) = store.objects._move_and_get_checksums(pid, input_stream)
        input_stream.close()
        store.objects.get_sha256_hex_digest(pid)
        assert os.path.isfile(abs_path) is True


def test_move_and_get_checksums_is_duplicate(pids, store):
    """Test move returns expected is_duplicate boolean value"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        # pylint: disable=W0212
        (
            _,
            _,
            _,
            is_duplicate,
            _,
        ) = store.objects._move_and_get_checksums(pid, input_stream)
        input_stream.close()
        store.objects.get_sha256_hex_digest(pid)
        assert is_duplicate is False


def test_move_and_get_checksums_duplicates(pids, store):
    """Test move does not store duplicate objects"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        # pylint: disable=W0212
        store.objects._move_and_get_checksums(pid, input_stream)
        input_stream.close()
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        # pylint: disable=W0212
        (
            _,
            _,
            _,
            is_duplicate,
            _,
        ) = store.objects._move_and_get_checksums(pid, input_stream)
        input_stream.close()
        assert is_duplicate is True
        assert store.objects.count() == 3


def test_mktempfile_hex_digests(pids, store):
    """Test _mktempfile returns correct hex digests"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        # pylint: disable=W0212
        hex_digests, _ = store.objects._mktempfile(input_stream)
        input_stream.close()
        assert hex_digests.get("md5") == pids[pid]["md5"]
        assert hex_digests.get("sha1") == pids[pid]["sha1"]
        assert hex_digests.get("sha256") == pids[pid]["sha256"]
        assert hex_digests.get("sha384") == pids[pid]["sha384"]
        assert hex_digests.get("sha512") == pids[pid]["sha512"]


def test_mktempfile_object(pids, store):
    """Test _mktempfile creates file successfully"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        # pylint: disable=W0212
        _, tmp_file_name = store.objects._mktempfile(input_stream)
        input_stream.close()
        assert os.path.isfile(tmp_file_name) is True


def test_mktempfile_with_algorithm(pids, store):
    """Test _mktempfile returns additional hex digest when supplied"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        algo = "sha224"
        # pylint: disable=W0212
        hex_digests, _ = store.objects._mktempfile(input_stream, algo)
        input_stream.close()
        assert hex_digests.get("sha224") == pids[pid]["sha224"]


def test_mktempfile_with_unsupported_algorithm(pids, store):
    """Test _mktempfile raises error when bad algorithm supplied"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        algo = "md2"
        with pytest.raises(ValueError):
            # pylint: disable=W0212
            _, _ = store.objects._mktempfile(input_stream, algo)
        input_stream.close()


def test_put_sysmeta(pids, store):
    """Test put sysmeta"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        ab_id = store.store_sysmeta(pid, syspath)
        assert store.sysmeta.exists(ab_id)
    assert store.sysmeta.count() == 3


def test_put_sysmeta_ab_id(pids, store):
    """Test put sysmeta"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        ab_id = store.store_sysmeta(pid, syspath)
        assert ab_id == pids[pid]["ab_id"]


def test_mktmpsysmeta(pids, store):
    """Test mktmpsysmeta creates tmpFile"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        sys_stream = io.open(syspath, "rb")
        namespace = "http://ns.dataone.org/service/types/v2.0"
        # pylint: disable=W0212
        tmp_name = store.sysmeta._mktmpsysmeta(sys_stream, namespace)
        sys_stream.close()
        assert store.sysmeta.exists(tmp_name)


def test_to_bytes(store):
    """Test _to_bytes returns bytes"""
    string = "teststring"
    # pylint: disable=W0212
    string_bytes = store.objects._to_bytes(string)
    assert isinstance(string_bytes, bytes)


def test_get_store_path_object(store):
    """Check get_store_path for object path"""
    # pylint: disable=W0212
    path_objects = store.objects._get_store_path()
    path_objects_string = str(path_objects)
    assert path_objects_string.endswith("/metacat/objects")


def test_get_store_path_sysmeta(store):
    """Check get_store_path for sysmeta path"""
    # pylint: disable=W0212
    path_sysmeta = store.sysmeta._get_store_path()
    path_sysmeta_string = str(path_sysmeta)
    assert path_sysmeta_string.endswith("/metacat/sysmeta")


def test_clean_algorithm(store):
    """Check that algorithm values get formatted as expected"""
    algorithm_underscore = "sha_256"
    algorithm_hyphen = "sha-256"
    algorithm_other_hyphen = "sha3-256"
    cleaned_algo_underscore = store.objects.clean_algorithm(algorithm_underscore)
    cleaned_algo_hyphen = store.objects.clean_algorithm(algorithm_hyphen)
    cleaned_algo_other_hyphen = store.objects.clean_algorithm(algorithm_other_hyphen)
    assert cleaned_algo_underscore == "sha256"
    assert cleaned_algo_hyphen == "sha256"
    assert cleaned_algo_other_hyphen == "sha3_256"


def test_get_sha256_hex_digest(pids, store):
    """Test for correct sha256 return value"""
    for pid in pids:
        hash_val = store.objects.get_sha256_hex_digest(pid)
        assert hash_val == pids[pid]["ab_id"]


def test_open(pids, store):
    """Test open returns a stream"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        io_buffer = store.objects.open(path)
        assert isinstance(io_buffer, io.BufferedReader)
        io_buffer.close()


def test_delete_by_id(pids, store):
    """Check objects are deleted after calling delete with id"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hash_address = store.objects.put(pid, path)
        hashaddress_id = hash_address.id
        store.objects.delete(hashaddress_id)
    assert store.objects.count() == 0


def test_delete_by_path(pids, store):
    """Check objects are deleted after calling delete with path"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hash_address = store.objects.put(pid, path)
        hashaddress_relpath = hash_address.relpath
        store.objects.delete(hashaddress_relpath)
    assert store.objects.count() == 0


def test_remove_empty_removes_empty_folders(store):
    """Test empty folders are removed"""
    three_dirs = "dir1/dir2/dir3"
    two_dirs = "dir1/dir4"
    one_dir = "dir5"
    os.makedirs(os.path.join(store.objects.root, three_dirs))
    os.makedirs(os.path.join(store.objects.root, two_dirs))
    os.makedirs(os.path.join(store.objects.root, one_dir))
    assert os.path.exists(os.path.join(store.objects.root, three_dirs))
    assert os.path.exists(os.path.join(store.objects.root, two_dirs))
    assert os.path.exists(os.path.join(store.objects.root, one_dir))
    store.objects.remove_empty(os.path.join(store.objects.root, three_dirs))
    store.objects.remove_empty(os.path.join(store.objects.root, two_dirs))
    store.objects.remove_empty(os.path.join(store.objects.root, one_dir))
    assert not os.path.exists(os.path.join(store.objects.root, three_dirs))
    assert not os.path.exists(os.path.join(store.objects.root, two_dirs))
    assert not os.path.exists(os.path.join(store.objects.root, one_dir))


def test_remove_empty_does_not_remove_nonempty_folders(pids, store):
    """Test non-empty folders are not removed"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hash_address = store.objects.put(pid, path)
        hashaddress_relpath = hash_address.relpath
        parent_dir = os.path.dirname(hashaddress_relpath)
        abs_parent_dir = store.objects.root + "/" + parent_dir
        store.objects.remove_empty(abs_parent_dir)
        assert os.path.exists(abs_parent_dir)


def test_haspath_subdirectory(store):
    """Test that subdirectory is recognized"""
    sub_dir = store.objects.root + "/filehashstore/test"
    os.makedirs(sub_dir)
    is_sub_dir = store.objects.haspath(sub_dir)
    assert is_sub_dir


def test_haspath_non_subdirectory(store):
    """Test that non-subdirectory is not recognized"""
    parent_dir = os.path.dirname(store.objects.root)
    non_sub_dir = parent_dir + "/filehashstore/test"
    os.makedirs(non_sub_dir)
    is_sub_dir = store.objects.haspath(non_sub_dir)
    assert not is_sub_dir


# TODO: Test count()


def test_makepath(pids, store):
    """Test makepath creates folder successfully"""
    for pid in pids:
        root_directory = store.objects.root
        pid_hex_digest_directory = pids[pid]["ab_id"][:2]
        pid_directory = root_directory + pid_hex_digest_directory
        store.objects.makepath(pid_directory)
        assert os.path.isdir(pid_directory)


def test_relpath(pids, store):
    """Test relpath returns the path relative to the root directory"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hashaddress = store.objects.put(pid, path)
        hashaddress_abspath = hashaddress.abspath
        rel_path = store.objects.relpath(hashaddress_abspath)
        assert rel_path.startswith(pids[pid]["ab_id"][:2])


def test_exists_with_absolute_path(pids, store):
    """Test exists method with an absolute file path"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hashaddress = store.objects.put(pid, path)
        hashaddress_abspath = hashaddress.abspath
        assert store.objects.exists(hashaddress_abspath)


def test_exists_with_relative_path(pids, store):
    """Test exists method with an absolute file path"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hashaddress = store.objects.put(pid, path)
        hashaddress_relpath = hashaddress.relpath
        assert store.objects.exists(hashaddress_relpath)


def test_exists_with_sharded_path(pids, store):
    """Test exists method with an absolute file path"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hashaddress = store.objects.put(pid, path)
        hashaddress_shard = store.objects.shard(hashaddress.id)
        hashaddress_shard_path = "/".join(hashaddress_shard)
        assert store.objects.exists(hashaddress_shard_path)


def test_exists_with_nonexistent_file(store):
    """Test exists method with a nonexistent file"""
    non_existent_file = "tests/testdata/filedoesnotexist"
    does_not_exist = store.objects.exists(non_existent_file)
    assert does_not_exist is False


def test_realpath_file_does_not_exist(store):
    """Test realpath returns None when object does not exist"""
    test_path = "tests/testdata/helloworld.txt"
    real_path_exists = store.objects.realpath(test_path)
    assert real_path_exists is None


def test_realpath_absolute_path(store, pids):
    """Test realpath returns True when absolute path exists"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hashaddress = store.objects.put(pid, path)
        hashaddress_abspath = hashaddress.abspath
        abs_path = store.objects.realpath(hashaddress_abspath)
        assert abs_path


def test_realpath_relative_path(store, pids):
    """Test realpath returns True when rel path exists"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hashaddress = store.objects.put(pid, path)
        hashaddress_relpath = hashaddress.relpath
        rel_path = store.objects.realpath(hashaddress_relpath)
        assert rel_path


def test_realpath_hex_digest_path(store, pids):
    """Test realpath returns True when rel path exists"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        hashaddress = store.objects.put(pid, path)
        hashaddress_id = hashaddress.id
        hex_digest = store.objects.realpath(hashaddress_id)
        assert hex_digest


def test_idpath(store, pids):
    """Test idpath builds the absolute file path"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        _ = store.objects.put(pid, path)
        id_path = store.objects.idpath(pids[pid]["ab_id"])
        assert id_path


def test_shard(store):
    """Test shard creates list"""
    hash_id = "0d555ed77052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e"
    predefined_list = [
        "0d",
        "55",
        "5e",
        "d77052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e",
    ]
    sharded_list = store.objects.shard(hash_id)
    assert predefined_list == sharded_list
