"""Test module for FileHashStore core, utility and supporting methods"""
import io
import os
from pathlib import Path
import pytest
from hashstore.filehashstore import FileHashStore


def test_pids_length(pids):
    """Ensure test harness pids are present."""
    assert len(pids) == 3


def test_init_directories_created(store):
    """Confirm that object and metadata directories have been created."""
    assert os.path.exists(store.root)
    assert os.path.exists(store.objects)
    assert os.path.exists(store.objects + "/tmp")
    assert os.path.exists(store.metadata)
    assert os.path.exists(store.metadata + "/tmp")
    assert os.path.exists(store.refs)
    assert os.path.exists(store.refs + "/pid")
    assert os.path.exists(store.refs + "/cid")


def test_init_existing_store_incorrect_algorithm_format(store):
    """Confirm that exception is thrown when store_algorithm is not a DataONE controlled value"""
    properties = {
        "store_path": store.root,
        "store_depth": 3,
        "store_width": 2,
        "store_algorithm": "sha256",
        "store_metadata_namespace": "http://ns.dataone.org/service/types/v2.0",
    }
    with pytest.raises(ValueError):
        FileHashStore(properties)


def test_init_existing_store_correct_algorithm_format(store):
    """Confirm second instance of HashStore with DataONE controlled value"""
    properties = {
        "store_path": store.root,
        "store_depth": 3,
        "store_width": 2,
        "store_algorithm": "SHA-256",
        "store_metadata_namespace": "http://ns.dataone.org/service/types/v2.0",
    }
    hashstore_instance = FileHashStore(properties)
    assert isinstance(hashstore_instance, FileHashStore)


def test_init_write_properties_hashstore_yaml_exists(store):
    """Verify config file present in store root directory."""
    assert os.path.exists(store.hashstore_configuration_yaml)


def test_init_with_existing_hashstore_mismatched_config_depth(store):
    """Test init with existing HashStore raises ValueError with mismatching properties."""
    properties = {
        "store_path": store.root,
        "store_depth": 1,
        "store_width": 2,
        "store_algorithm": "SHA-256",
        "store_metadata_namespace": "http://ns.dataone.org/service/types/v2.0",
    }
    with pytest.raises(ValueError):
        FileHashStore(properties)


def test_init_with_existing_hashstore_mismatched_config_width(store):
    """Test init with existing HashStore raises ValueError with mismatching properties."""
    properties = {
        "store_path": store.root,
        "store_depth": 3,
        "store_width": 1,
        "store_algorithm": "SHA-256",
        "store_metadata_namespace": "http://ns.dataone.org/service/types/v2.0",
    }
    with pytest.raises(ValueError):
        FileHashStore(properties)


def test_init_with_existing_hashstore_mismatched_config_algo(store):
    """Test init with existing HashStore raises ValueError with mismatching properties."""
    properties = {
        "store_path": store.root,
        "store_depth": 3,
        "store_width": 1,
        "store_algorithm": "SHA-512",
        "store_metadata_namespace": "http://ns.dataone.org/service/types/v2.0",
    }
    with pytest.raises(ValueError):
        FileHashStore(properties)


def test_init_with_existing_hashstore_mismatched_config_metadata_ns(store):
    """Test init with existing HashStore raises ValueError with mismatching properties."""
    properties = {
        "store_path": store.root,
        "store_depth": 3,
        "store_width": 1,
        "store_algorithm": "SHA-512",
        "store_metadata_namespace": "http://ns.dataone.org/service/types/v5.0",
    }
    with pytest.raises(ValueError):
        FileHashStore(properties)


def test_init_with_existing_hashstore_missing_yaml(store, pids):
    """Test init with existing store raises FileNotFoundError when hashstore.yaml
    not found but objects exist."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        store.put_object(pid, path)
    os.remove(store.hashstore_configuration_yaml)
    properties = {
        "store_path": store.root,
        "store_depth": 3,
        "store_width": 2,
        "store_algorithm": "SHA-256",
        "store_metadata_namespace": "http://ns.dataone.org/service/types/v2.0",
    }
    with pytest.raises(FileNotFoundError):
        FileHashStore(properties)


def test_load_properties(store):
    """Verify dictionary returned from load_properties matches initialization."""
    hashstore_yaml_dict = store.load_properties()
    assert hashstore_yaml_dict.get("store_depth") == 3
    assert hashstore_yaml_dict.get("store_width") == 2
    assert hashstore_yaml_dict.get("store_algorithm") == "SHA-256"
    assert (
        hashstore_yaml_dict.get("store_metadata_namespace")
        == "http://ns.dataone.org/service/types/v2.0"
    )


def test_load_properties_hashstore_yaml_missing(store):
    """Confirm FileNotFoundError is raised when hashstore.yaml does not exist."""
    os.remove(store.hashstore_configuration_yaml)
    with pytest.raises(FileNotFoundError):
        store.load_properties()


def test_validate_properties(store):
    """Confirm properties validated when all key/values are supplied."""
    properties = {
        "store_path": "/etc/test",
        "store_depth": 3,
        "store_width": 2,
        "store_algorithm": "SHA-256",
        "store_metadata_namespace": "http://ns.dataone.org/service/types/v2.0",
    }
    # pylint: disable=W0212
    assert store._validate_properties(properties)


def test_validate_properties_missing_key(store):
    """Confirm exception raised when key missing in properties."""
    properties = {
        "store_path": "/etc/test",
        "store_depth": 3,
        "store_width": 2,
        "store_algorithm": "SHA-256",
    }
    with pytest.raises(KeyError):
        # pylint: disable=W0212
        store._validate_properties(properties)


def test_validate_properties_key_value_is_none(store):
    """Confirm exception raised when value from key is 'None'."""
    properties = {
        "store_path": "/etc/test",
        "store_depth": 3,
        "store_width": 2,
        "store_algorithm": "SHA-256",
        "store_metadata_namespace": None,
    }
    with pytest.raises(ValueError):
        # pylint: disable=W0212
        store._validate_properties(properties)


def test_validate_properties_incorrect_type(store):
    """Confirm exception raised when key missing in properties."""
    properties = "etc/filehashstore/hashstore.yaml"
    with pytest.raises(ValueError):
        # pylint: disable=W0212
        store._validate_properties(properties)


def test_set_default_algorithms_missing_yaml(store, pids):
    """Confirm set_default_algorithms raises FileNotFoundError when hashstore.yaml
    not found."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        store.put_object(pid, path)
    os.remove(store.hashstore_configuration_yaml)
    with pytest.raises(FileNotFoundError):
        # pylint: disable=W0212
        store._set_default_algorithms()


def test_put_object_files_path(pids, store):
    """Test put objects with path object."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        path = Path(test_dir) / pid.replace("/", "_")
        object_metadata = store.put_object(pid, path)
        object_metadata_id = object_metadata.id
        assert store.exists(entity, object_metadata_id)


def test_put_object_files_string(pids, store):
    """Test put objects with string."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.put_object(pid, path)
        object_metadata_id = object_metadata.id
        assert store.exists(entity, object_metadata_id)


def test_put_object_files_stream(pids, store):
    """Test put objects with stream."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        object_metadata = store.put_object(pid, input_stream)
        input_stream.close()
        object_metadata_id = object_metadata.id
        assert store.exists(entity, object_metadata_id)
    assert store.count(entity) == 3


def test_put_object_cid(pids, store):
    """Check put returns correct id."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.put_object(pid, path)
        object_metadata_id = object_metadata.id
        assert object_metadata_id == pids[pid][store.algorithm]


def test_put_object_file_size(pids, store):
    """Check put returns correct file size."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.put_object(pid, path)
        object_size = object_metadata.obj_size
        assert object_size == pids[pid]["file_size_bytes"]


def test_put_object_hex_digests(pids, store):
    """Check put successfully generates hex digests dictionary."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.put_object(pid, path)
        object_metadata_hex_digests = object_metadata.hex_digests
        assert object_metadata_hex_digests.get("md5") == pids[pid]["md5"]
        assert object_metadata_hex_digests.get("sha1") == pids[pid]["sha1"]
        assert object_metadata_hex_digests.get("sha256") == pids[pid]["sha256"]
        assert object_metadata_hex_digests.get("sha384") == pids[pid]["sha384"]
        assert object_metadata_hex_digests.get("sha512") == pids[pid]["sha512"]


def test_put_object_additional_algorithm(pids, store):
    """Check put_object returns additional algorithm in hex digests."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        algo = "sha224"
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.put_object(pid, path, additional_algorithm=algo)
        hex_digests = object_metadata.hex_digests
        sha224_hash = hex_digests.get(algo)
        assert sha224_hash == pids[pid][algo]


def test_put_object_with_correct_checksums(pids, store):
    """Check put_object success with valid checksum and checksum algorithm supplied."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        algo = "sha224"
        algo_checksum = pids[pid][algo]
        path = test_dir + pid.replace("/", "_")
        store.put_object(pid, path, checksum=algo_checksum, checksum_algorithm=algo)
    assert store.count("objects") == 3


def test_put_object_with_incorrect_checksum(pids, store):
    """Check put fails when bad checksum supplied."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        algo = "sha224"
        algo_checksum = "badChecksumValue"
        path = test_dir + pid.replace("/", "_")
        with pytest.raises(ValueError):
            store.put_object(pid, path, checksum=algo_checksum, checksum_algorithm=algo)
    assert store.count(entity) == 0


def test_move_and_get_checksums_id(pids, store):
    """Test move returns correct id."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        # pylint: disable=W0212
        (
            move_id,
            _,
            _,
        ) = store._move_and_get_checksums(pid, input_stream)
        input_stream.close()
        assert move_id == pids[pid][store.algorithm]


def test_move_and_get_checksums_file_size(pids, store):
    """Test move returns correct file size."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        # pylint: disable=W0212
        (
            _,
            tmp_file_size,
            _,
        ) = store._move_and_get_checksums(pid, input_stream)
        input_stream.close()
        assert tmp_file_size == pids[pid]["file_size_bytes"]


def test_move_and_get_checksums_hex_digests(pids, store):
    """Test move returns correct hex digests."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        # pylint: disable=W0212
        (
            _,
            _,
            hex_digests,
        ) = store._move_and_get_checksums(pid, input_stream)
        input_stream.close()
        assert hex_digests.get("md5") == pids[pid]["md5"]
        assert hex_digests.get("sha1") == pids[pid]["sha1"]
        assert hex_digests.get("sha256") == pids[pid]["sha256"]
        assert hex_digests.get("sha384") == pids[pid]["sha384"]
        assert hex_digests.get("sha512") == pids[pid]["sha512"]


def test_move_and_get_checksums_duplicates_raises_error(pids, store):
    """Test move does not store duplicate objects and raises error."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        # pylint: disable=W0212
        store._move_and_get_checksums(pid, input_stream)
        input_stream.close()
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        with pytest.raises(FileExistsError):
            # pylint: disable=W0212
            store._move_and_get_checksums(pid, input_stream)
            input_stream.close()
    assert store.count(entity) == 3


def test_move_and_get_checksums_file_size_raises_error(pids, store):
    """Test move and get checksum raises error with incorrect file size"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        with pytest.raises(ValueError):
            path = test_dir + pid.replace("/", "_")
            input_stream = io.open(path, "rb")
            incorrect_file_size = 1000
            # pylint: disable=W0212
            (
                _,
                _,
                _,
                _,
            ) = store._move_and_get_checksums(
                pid, input_stream, file_size_to_validate=incorrect_file_size
            )
            input_stream.close()


def test_mktempfile_additional_algo(store):
    """Test _mktempfile returns correct hex digests for additional algorithm."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    input_stream = io.open(path, "rb")
    checksum_algo = "sha3_256"
    checksum_correct = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    # pylint: disable=W0212
    hex_digests, _, _ = store._mktmpfile(
        input_stream, additional_algorithm=checksum_algo
    )
    input_stream.close()
    assert hex_digests.get("sha3_256") == checksum_correct


def test_mktempfile_checksum_algo(store):
    """Test _mktempfile returns correct hex digests for checksum algorithm."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    input_stream = io.open(path, "rb")
    checksum_algo = "sha3_256"
    checksum_correct = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    # pylint: disable=W0212
    hex_digests, _, _ = store._mktmpfile(input_stream, checksum_algorithm=checksum_algo)
    input_stream.close()
    assert hex_digests.get("sha3_256") == checksum_correct


def test_mktempfile_checksum_and_additional_algo(store):
    """Test _mktempfile returns correct hex digests for checksum algorithm."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    input_stream = io.open(path, "rb")
    additional_algo = "sha224"
    additional_algo_checksum = (
        "9b3a96f434f3c894359193a63437ef86fbd5a1a1a6cc37f1d5013ac1"
    )
    checksum_algo = "sha3_256"
    checksum_correct = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    # pylint: disable=W0212
    hex_digests, _, _ = store._mktmpfile(
        input_stream,
        additional_algorithm=additional_algo,
        checksum_algorithm=checksum_algo,
    )
    input_stream.close()
    assert hex_digests.get("sha3_256") == checksum_correct
    assert hex_digests.get("sha224") == additional_algo_checksum


def test_mktempfile_checksum_and_additional_algo_duplicate(store):
    """Test _mktempfile succeeds with duplicate algorithms (de-duplicates)."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    input_stream = io.open(path, "rb")
    additional_algo = "sha224"
    checksum_algo = "sha224"
    checksum_correct = "9b3a96f434f3c894359193a63437ef86fbd5a1a1a6cc37f1d5013ac1"
    # pylint: disable=W0212
    hex_digests, _, _ = store._mktmpfile(
        input_stream,
        additional_algorithm=additional_algo,
        checksum_algorithm=checksum_algo,
    )
    input_stream.close()
    assert hex_digests.get("sha224") == checksum_correct


def test_mktempfile_file_size(pids, store):
    """Test _mktempfile returns correct file size."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        # pylint: disable=W0212
        _, _, tmp_file_size = store._mktmpfile(input_stream)
        input_stream.close()
        assert tmp_file_size == pids[pid]["file_size_bytes"]


def test_mktempfile_hex_digests(pids, store):
    """Test _mktempfile returns correct hex digests."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        # pylint: disable=W0212
        hex_digests, _, _ = store._mktmpfile(input_stream)
        input_stream.close()
        assert hex_digests.get("md5") == pids[pid]["md5"]
        assert hex_digests.get("sha1") == pids[pid]["sha1"]
        assert hex_digests.get("sha256") == pids[pid]["sha256"]
        assert hex_digests.get("sha384") == pids[pid]["sha384"]
        assert hex_digests.get("sha512") == pids[pid]["sha512"]


def test_mktempfile_tmpfile_object(pids, store):
    """Test _mktempfile creates file successfully."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        # pylint: disable=W0212
        _, tmp_file_name, _ = store._mktmpfile(input_stream)
        input_stream.close()
        assert os.path.isfile(tmp_file_name) is True


def test_mktempfile_with_unsupported_algorithm(pids, store):
    """Test _mktempfile raises error when bad algorithm supplied."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        algo = "md2"
        with pytest.raises(ValueError):
            # pylint: disable=W0212
            _, _, _ = store._mktmpfile(input_stream, additional_algorithm=algo)
        with pytest.raises(ValueError):
            # pylint: disable=W0212
            _, _, _ = store._mktmpfile(input_stream, checksum_algorithm=algo)
        input_stream.close()


def test_put_metadata_with_path(pids, store):
    """Test put_metadata with path object."""
    entity = "metadata"
    test_dir = "tests/testdata/"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        metadata_cid = store.store_metadata(pid, syspath, format_id)
        assert store.exists(entity, metadata_cid)
    assert store.count(entity) == 3


def test_put_metadata_with_string(pids, store):
    """Test_put metadata with string."""
    entity = "metadata"
    test_dir = "tests/testdata/"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = str(Path(test_dir) / filename)
        metadata_cid = store.store_metadata(pid, syspath, format_id)
        assert store.exists(entity, metadata_cid)
    assert store.count(entity) == 3


def test_put_metadata_cid(pids, store):
    """Test put metadata returns correct id."""
    test_dir = "tests/testdata/"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        metadata_cid = store.store_metadata(pid, syspath, format_id)
        assert metadata_cid == pids[pid]["metadata_cid"]


def test_mktmpmetadata(pids, store):
    """Test mktmpmetadata creates tmpFile."""
    test_dir = "tests/testdata/"
    entity = "metadata"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        sys_stream = io.open(syspath, "rb")
        # pylint: disable=W0212
        tmp_name = store._mktmpmetadata(sys_stream)
        sys_stream.close()
        assert store.exists(entity, tmp_name)


def test_clean_algorithm(store):
    """Check that algorithm values get formatted as expected."""
    algorithm_underscore = "sha_256"
    algorithm_hyphen = "sha-256"
    algorithm_other_hyphen = "sha3-256"
    cleaned_algo_underscore = store.clean_algorithm(algorithm_underscore)
    cleaned_algo_hyphen = store.clean_algorithm(algorithm_hyphen)
    cleaned_algo_other_hyphen = store.clean_algorithm(algorithm_other_hyphen)
    assert cleaned_algo_underscore == "sha256"
    assert cleaned_algo_hyphen == "sha256"
    assert cleaned_algo_other_hyphen == "sha3_256"


def test_computehash(pids, store):
    """Test to check computehash method."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        obj_stream = io.open(path, "rb")
        obj_sha256_hash = store.computehash(obj_stream, "sha256")
        obj_stream.close()
        assert pids[pid]["sha256"] == obj_sha256_hash


def test_get_store_path_object(store):
    """Check get_store_path for object path."""
    # pylint: disable=W0212
    path_objects = store.get_store_path("objects")
    path_objects_string = str(path_objects)
    assert path_objects_string.endswith("/metacat/objects")


def test_get_store_path_metadata(store):
    """Check get_store_path for metadata path."""
    # pylint: disable=W0212
    path_metadata = store.get_store_path("metadata")
    path_metadata_string = str(path_metadata)
    assert path_metadata_string.endswith("/metacat/metadata")


def test_exists_with_object_metadata_id(pids, store):
    """Test exists method with an absolute file path."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.put_object(pid, path)
        assert store.exists(entity, object_metadata.id)


def test_exists_with_sharded_path(pids, store):
    """Test exists method with an absolute file path."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.put_object(pid, path)
        object_metadata_shard = store.shard(object_metadata.id)
        object_metadata_shard_path = "/".join(object_metadata_shard)
        assert store.exists(entity, object_metadata_shard_path)


def test_exists_with_nonexistent_file(store):
    """Test exists method with a nonexistent file."""
    entity = "objects"
    non_existent_file = "tests/testdata/filedoesnotexist"
    does_not_exist = store.exists(entity, non_existent_file)
    assert does_not_exist is False


def test_shard(store):
    """Test shard creates list."""
    hash_id = "0d555ed77052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e"
    predefined_list = [
        "0d",
        "55",
        "5e",
        "d77052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e",
    ]
    sharded_list = store.shard(hash_id)
    assert predefined_list == sharded_list


def test_open_objects(pids, store):
    """Test open returns a stream."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.put_object(pid, path)
        object_metadata_id = object_metadata.id
        io_buffer = store.open(entity, object_metadata_id)
        assert isinstance(io_buffer, io.BufferedReader)
        io_buffer.close()


def test_delete_by_object_metadata_id(pids, store):
    """Check objects are deleted after calling delete with hash address id."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.put_object(pid, path)
        object_metadata_id = object_metadata.id
        store.delete(entity, object_metadata_id)
    assert store.count(entity) == 0


def test_remove_empty_removes_empty_folders_string(store):
    """Test empty folders (via string) are removed."""
    three_dirs = "dir1/dir2/dir3"
    two_dirs = "dir1/dir4"
    one_dir = "dir5"
    os.makedirs(os.path.join(store.root, three_dirs))
    os.makedirs(os.path.join(store.root, two_dirs))
    os.makedirs(os.path.join(store.root, one_dir))
    assert os.path.exists(os.path.join(store.root, three_dirs))
    assert os.path.exists(os.path.join(store.root, two_dirs))
    assert os.path.exists(os.path.join(store.root, one_dir))
    store.remove_empty(os.path.join(store.root, three_dirs))
    store.remove_empty(os.path.join(store.root, two_dirs))
    store.remove_empty(os.path.join(store.root, one_dir))
    assert not os.path.exists(os.path.join(store.root, three_dirs))
    assert not os.path.exists(os.path.join(store.root, two_dirs))
    assert not os.path.exists(os.path.join(store.root, one_dir))


def test_remove_empty_removes_empty_folders_path(store):
    """Test empty folders (via Path object) are removed."""
    three_dirs = Path("dir1/dir2/dir3")
    two_dirs = Path("dir1/dir4")
    one_dir = Path("dir5")
    (store.root / three_dirs).mkdir(parents=True)
    (store.root / two_dirs).mkdir(parents=True)
    (store.root / one_dir).mkdir(parents=True)
    assert (store.root / three_dirs).exists()
    assert (store.root / two_dirs).exists()
    assert (store.root / one_dir).exists()
    store.remove_empty(store.root / three_dirs)
    store.remove_empty(store.root / two_dirs)
    store.remove_empty(store.root / one_dir)
    assert not (store.root / three_dirs).exists()
    assert not (store.root / two_dirs).exists()
    assert not (store.root / one_dir).exists()


def test_remove_empty_does_not_remove_nonempty_folders(pids, store):
    """Test non-empty folders are not removed."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.put_object(pid, path)
        object_metadata_shard = store.shard(object_metadata.id)
        object_metadata_shard_path = "/".join(object_metadata_shard)
        # Get parent directory of the relative path
        parent_dir = os.path.dirname(object_metadata_shard_path)
        # Attempt to remove the parent directory
        store.remove_empty(parent_dir)
        abs_parent_dir = store.objects + "/" + parent_dir
        assert os.path.exists(abs_parent_dir)


def test_has_subdir_subdirectory_string(store):
    """Test that subdirectory is recognized."""
    sub_dir = store.root + "/filehashstore/test"
    os.makedirs(sub_dir)
    # pylint: disable=W0212
    is_sub_dir = store._has_subdir(sub_dir)
    assert is_sub_dir


def test_has_subdir_subdirectory_path(store):
    """Test that subdirectory is recognized."""
    sub_dir = Path(store.root) / "filehashstore" / "test"
    sub_dir.mkdir(parents=True)
    # pylint: disable=W0212
    is_sub_dir = store._has_subdir(sub_dir)
    assert is_sub_dir


def test_has_subdir_non_subdirectory(store):
    """Test that non-subdirectory is not recognized."""
    parent_dir = os.path.dirname(store.root)
    non_sub_dir = parent_dir + "/filehashstore/test"
    os.makedirs(non_sub_dir)
    # pylint: disable=W0212
    is_sub_dir = store._has_subdir(non_sub_dir)
    assert not is_sub_dir


def test_create_path(pids, store):
    """Test makepath creates folder successfully."""
    for pid in pids:
        root_directory = store.root
        pid_hex_digest_directory = pids[pid]["metadata_cid"][:2]
        pid_directory = root_directory + pid_hex_digest_directory
        store.create_path(pid_directory)
        assert os.path.isdir(pid_directory)


def test_get_real_path_file_does_not_exist(store):
    """Test get_real_path returns None when object does not exist."""
    entity = "objects"
    test_path = "tests/testdata/helloworld.txt"
    real_path_exists = store.get_real_path(entity, test_path)
    assert real_path_exists is None


def test_get_real_path_with_object_id(store, pids):
    """Test get_real_path returns absolute path given an object id."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.put_object(pid, path)
        obj_abs_path = store.get_real_path(entity, object_metadata.id)
        assert os.path.exists(obj_abs_path)


def test_get_real_path_with_object_id_sharded(pids, store):
    """Test exists method with a sharded path (relative path)."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.put_object(pid, path)
        object_metadata_shard = store.shard(object_metadata.id)
        object_metadata_shard_path = "/".join(object_metadata_shard)
        obj_abs_path = store.get_real_path(entity, object_metadata_shard_path)
        assert os.path.exists(obj_abs_path)


def test_get_real_path_with_metadata_id(store, pids):
    """Test get_real_path returns absolute path given a metadata id."""
    entity = "metadata"
    test_dir = "tests/testdata/"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        metadata_cid = store.store_metadata(pid, syspath, format_id)
        metadata_abs_path = store.get_real_path(entity, metadata_cid)
        assert os.path.exists(metadata_abs_path)


def test_get_real_path_with_bad_entity(store, pids):
    """Test get_real_path returns absolute path given an object id."""
    test_dir = "tests/testdata/"
    entity = "bad_entity"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.put_object(pid, path)
        with pytest.raises(ValueError):
            store.get_real_path(entity, object_metadata.id)


def test_build_abs_path(store, pids):
    """Test build_abs_path builds the absolute file path."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        _ = store.put_object(pid, path)
        # pylint: disable=W0212
        abs_path = store.build_abs_path(entity, pids[pid]["object_cid"])
        assert abs_path


def test_count(pids, store):
    """Check that count returns expected number of objects."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        path_string = test_dir + pid.replace("/", "_")
        store.put_object(pid, path_string)
    assert store.count(entity) == 3


def test_to_bytes(store):
    """Test _to_bytes returns bytes."""
    string = "teststring"
    # pylint: disable=W0212
    string_bytes = store._to_bytes(string)
    assert isinstance(string_bytes, bytes)


def test_get_sha256_hex_digest(pids, store):
    """Test for correct sha256 return value."""
    for pid in pids:
        hash_val = store.get_sha256_hex_digest(pid)
        assert hash_val == pids[pid]["object_cid"]
