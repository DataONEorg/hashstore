"""Test module for FileHashStore init, core, utility and supporting methods."""

import io
import os
import hashlib
import shutil
from pathlib import Path
import pytest
from hashstore.filehashstore import FileHashStore, ObjectMetadata, Stream
from hashstore.filehashstore_exceptions import (
    OrphanPidRefsFileFound,
    NonMatchingChecksum,
    NonMatchingObjSize,
    PidNotFoundInCidRefsFile,
    PidRefsDoesNotExist,
    RefsFileExistsButCidObjMissing,
    UnsupportedAlgorithm,
    HashStoreRefsAlreadyExists,
    PidRefsAlreadyExistsError,
    CidRefsContentError,
    CidRefsFileNotFound,
    PidRefsContentError,
    PidRefsFileNotFound,
    IdentifierNotLocked,
)


# pylint: disable=W0212


def test_init_directories_created(store):
    """Confirm that object and metadata directories have been created."""
    assert os.path.exists(store.root)
    assert os.path.exists(store.objects)
    assert os.path.exists(store.objects / "tmp")
    assert os.path.exists(store.metadata)
    assert os.path.exists(store.metadata / "tmp")
    assert os.path.exists(store.refs)
    assert os.path.exists(store.refs / "tmp")
    assert os.path.exists(store.refs / "pids")
    assert os.path.exists(store.refs / "cids")


def test_init_existing_store_incorrect_algorithm_format(store):
    """Confirm that exception is thrown when store_algorithm is not a DataONE controlled value (
    the string must exactly match the expected format). DataONE uses the library of congress
    vocabulary to standardize algorithm types."""
    properties = {
        "store_path": store.root / "incorrect_algo_format",
        "store_depth": 3,
        "store_width": 2,
        "store_algorithm": "sha256",
        "store_metadata_namespace": "https://ns.dataone.org/service/types/v2.0#SystemMetadata",
    }
    with pytest.raises(ValueError):
        FileHashStore(properties)


def test_init_existing_store_correct_algorithm_format(store):
    """Confirm second instance of HashStore with DataONE controlled value."""
    properties = {
        "store_path": store.root,
        "store_depth": 3,
        "store_width": 2,
        "store_algorithm": "SHA-256",
        "store_metadata_namespace": "https://ns.dataone.org/service/types/v2.0#SystemMetadata",
    }
    hashstore_instance = FileHashStore(properties)
    assert isinstance(hashstore_instance, FileHashStore)


def test_init_write_properties_hashstore_yaml_exists(store):
    """Verify config file present in store root directory."""
    assert os.path.exists(store.hashstore_configuration_yaml)


def test_init_with_existing_hashstore_mismatched_config_depth(store):
    """Test init with existing HashStore raises a ValueError when supplied with
    mismatching depth."""
    properties = {
        "store_path": store.root,
        "store_depth": 1,
        "store_width": 2,
        "store_algorithm": "SHA-256",
        "store_metadata_namespace": "https://ns.dataone.org/service/types/v2.0#SystemMetadata",
    }
    with pytest.raises(ValueError):
        FileHashStore(properties)


def test_init_with_existing_hashstore_mismatched_config_width(store):
    """Test init with existing HashStore raises a ValueError when supplied with
    mismatching width."""
    properties = {
        "store_path": store.root,
        "store_depth": 3,
        "store_width": 1,
        "store_algorithm": "SHA-256",
        "store_metadata_namespace": "https://ns.dataone.org/service/types/v2.0#SystemMetadata",
    }
    with pytest.raises(ValueError):
        FileHashStore(properties)


def test_init_with_existing_hashstore_mismatched_config_algo(store):
    """Test init with existing HashStore raises a ValueError when supplied with
    mismatching default algorithm."""
    properties = {
        "store_path": store.root,
        "store_depth": 3,
        "store_width": 1,
        "store_algorithm": "SHA-512",
        "store_metadata_namespace": "https://ns.dataone.org/service/types/v2.0#SystemMetadata",
    }
    with pytest.raises(ValueError):
        FileHashStore(properties)


def test_init_with_existing_hashstore_mismatched_config_metadata_ns(store):
    """Test init with existing HashStore raises a ValueError when supplied with
    mismatching default name space."""
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
    """Test init with existing store raises RuntimeError when hashstore.yaml
    not found but objects exist."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        store._store_and_validate_data(pid, path)
    os.remove(store.hashstore_configuration_yaml)
    properties = {
        "store_path": store.root,
        "store_depth": 3,
        "store_width": 2,
        "store_algorithm": "SHA-256",
        "store_metadata_namespace": "https://ns.dataone.org/service/types/v2.0#SystemMetadata",
    }
    with pytest.raises(RuntimeError):
        FileHashStore(properties)


def test_load_properties(store):
    """Verify dictionary returned from _load_properties matches initialization."""
    hashstore_yaml_dict = store._load_properties(
        store.hashstore_configuration_yaml, store.property_required_keys
    )
    assert hashstore_yaml_dict.get("store_depth") == 3
    assert hashstore_yaml_dict.get("store_width") == 2
    assert hashstore_yaml_dict.get("store_algorithm") == "SHA-256"
    assert (
        hashstore_yaml_dict.get("store_metadata_namespace")
        == "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    )


def test_load_properties_hashstore_yaml_missing(store):
    """Confirm FileNotFoundError is raised when hashstore.yaml does not exist."""
    os.remove(store.hashstore_configuration_yaml)
    with pytest.raises(FileNotFoundError):
        store._load_properties(
            store.hashstore_configuration_yaml, store.property_required_keys
        )


def test_validate_properties(store):
    """Confirm no exceptions are thrown when all key/values are supplied."""
    properties = {
        "store_path": "/etc/test",
        "store_depth": 3,
        "store_width": 2,
        "store_algorithm": "SHA-256",
        "store_metadata_namespace": "https://ns.dataone.org/service/types/v2.0#SystemMetadata",
    }
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
        store._validate_properties(properties)


def test_validate_properties_key_value_is_none(store):
    """Confirm exception raised when a value from a key is 'None'."""
    properties = {
        "store_path": "/etc/test",
        "store_depth": 3,
        "store_width": 2,
        "store_algorithm": "SHA-256",
        "store_metadata_namespace": None,
    }
    with pytest.raises(ValueError):
        store._validate_properties(properties)


def test_validate_properties_incorrect_type(store):
    """Confirm exception raised when a bad properties value is given."""
    properties = "etc/filehashstore/hashstore.yaml"
    with pytest.raises(ValueError):
        store._validate_properties(properties)


def test_set_default_algorithms_missing_yaml(store, pids):
    """Confirm set_default_algorithms raises FileNotFoundError when hashstore.yaml
    not found."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        store._store_and_validate_data(pid, path)
    os.remove(store.hashstore_configuration_yaml)
    with pytest.raises(FileNotFoundError):
        store._set_default_algorithms()


# Tests for FileHashStore Core Methods


def test_find_object_no_sysmeta(pids, store):
    """Test _find_object returns the correct content and expected value for non-existent sysmeta."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)
        obj_info_dict = store._find_object(pid)
        retrieved_cid = obj_info_dict["cid"]

        assert retrieved_cid == object_metadata.hex_digests.get("sha256")

        data_object_path = store._get_hashstore_data_object_path(retrieved_cid)
        assert data_object_path == obj_info_dict["cid_object_path"]

        cid_refs_path = store._get_hashstore_cid_refs_path(retrieved_cid)
        assert cid_refs_path == obj_info_dict["cid_refs_path"]

        pid_refs_path = store._get_hashstore_pid_refs_path(pid)
        assert pid_refs_path == obj_info_dict["pid_refs_path"]

        assert obj_info_dict["sysmeta_path"] == "Does not exist."


def test_find_object_sysmeta(pids, store):
    """Test _find_object returns the correct content along with the sysmeta path"""
    test_dir = "tests/testdata/"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        object_metadata = store.store_object(pid, path)
        stored_metadata_path = store.store_metadata(pid, syspath, format_id)

        obj_info_dict = store._find_object(pid)
        retrieved_cid = obj_info_dict["cid"]

        assert retrieved_cid == object_metadata.hex_digests.get("sha256")

        data_object_path = store._get_hashstore_data_object_path(retrieved_cid)
        assert data_object_path == obj_info_dict["cid_object_path"]

        cid_refs_path = store._get_hashstore_cid_refs_path(retrieved_cid)
        assert cid_refs_path == obj_info_dict["cid_refs_path"]

        pid_refs_path = store._get_hashstore_pid_refs_path(pid)
        assert pid_refs_path == obj_info_dict["pid_refs_path"]

        assert str(obj_info_dict["sysmeta_path"]) == stored_metadata_path


def test_find_object_refs_exist_but_obj_not_found(pids, store):
    """Test _find_object throws exception when refs file exist but the object does not."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        store.store_object(pid, path)

        cid = store._find_object(pid).get("cid")
        obj_path = store._get_hashstore_data_object_path(cid)
        os.remove(obj_path)

        with pytest.raises(RefsFileExistsButCidObjMissing):
            store._find_object(pid)


def test_find_object_cid_refs_not_found(pids, store):
    """Test _find_object throws exception when pid refs file is found (and contains a cid)
    but the cid refs file does not exist."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        _object_metadata = store.store_object(pid, path)

        # Place the wrong cid into the pid refs file that has already been created
        pid_ref_abs_path = store._get_hashstore_pid_refs_path(pid)
        with open(pid_ref_abs_path, "w", encoding="utf8") as pid_ref_file:
            pid_ref_file.seek(0)
            pid_ref_file.write("intentionally.wrong.pid")
            pid_ref_file.truncate()

        with pytest.raises(OrphanPidRefsFileFound):
            store._find_object(pid)


def test_find_object_cid_refs_does_not_contain_pid(pids, store):
    """Test _find_object throws exception when pid refs file is found (and contains a cid)
    but the cid refs file does not contain the pid."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)

        # Remove the pid from the cid refs file
        cid_ref_abs_path = store._get_hashstore_cid_refs_path(
            object_metadata.hex_digests.get("sha256")
        )
        store._update_refs_file(cid_ref_abs_path, pid, "remove")

        with pytest.raises(PidNotFoundInCidRefsFile):
            store._find_object(pid)


def test_find_object_pid_refs_not_found(store):
    """Test _find_object throws exception when a pid refs file does not exist."""
    with pytest.raises(PidRefsDoesNotExist):
        store._find_object("dou.test.1")


def test_find_object_pid_none(store):
    """Test _find_object throws exception when pid is None."""
    with pytest.raises(ValueError):
        store._find_object(None)


def test_find_object_pid_empty(store):
    """Test _find_object throws exception when pid is empty."""
    with pytest.raises(ValueError):
        store._find_object("")


def test_store_and_validate_data_files_path(pids, store):
    """Test _store_and_validate_data accepts path object for the path arg."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = Path(test_dir) / pid.replace("/", "_")
        object_metadata = store._store_and_validate_data(pid, path)
        assert store._exists("objects", object_metadata.cid)


def test_store_and_validate_data_files_string(pids, store):
    """Test _store_and_validate_data accepts string for the path arg."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store._store_and_validate_data(pid, path)
        assert store._exists("objects", object_metadata.cid)


def test_store_and_validate_data_files_stream(pids, store):
    """Test _store_and_validate_data accepts stream for the path arg."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        object_metadata = store._store_and_validate_data(pid, input_stream)
        input_stream.close()
        assert store._exists("objects", object_metadata.cid)
    assert store._count("objects") == 3


def test_store_and_validate_data_cid(pids, store):
    """Check _store_and_validate_data returns the expected content identifier"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store._store_and_validate_data(pid, path)
        assert object_metadata.cid == pids[pid][store.algorithm]


def test_store_and_validate_data_file_size(pids, store):
    """Check _store_and_validate_data returns correct file size."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store._store_and_validate_data(pid, path)
        assert object_metadata.obj_size == pids[pid]["file_size_bytes"]


def test_store_and_validate_data_hex_digests(pids, store):
    """Check _store_and_validate_data successfully generates hex digests dictionary."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store._store_and_validate_data(pid, path)
        assert object_metadata.hex_digests.get("md5") == pids[pid]["md5"]
        assert object_metadata.hex_digests.get("sha1") == pids[pid]["sha1"]
        assert object_metadata.hex_digests.get("sha256") == pids[pid]["sha256"]
        assert object_metadata.hex_digests.get("sha384") == pids[pid]["sha384"]
        assert object_metadata.hex_digests.get("sha512") == pids[pid]["sha512"]


def test_store_and_validate_data_additional_algorithm(pids, store):
    """Check _store_and_validate_data returns an additional algorithm in hex digests
    when provided with an additional algo value."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        algo = "sha224"
        path = test_dir + pid.replace("/", "_")
        object_metadata = store._store_and_validate_data(
            pid, path, additional_algorithm=algo
        )
        sha224_hash = object_metadata.hex_digests.get(algo)
        assert sha224_hash == pids[pid][algo]


def test_store_and_validate_data_with_correct_checksums(pids, store):
    """Check _store_and_validate_data stores a data object when a valid checksum and checksum
    algorithm is supplied."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        algo = "sha224"
        algo_checksum = pids[pid][algo]
        path = test_dir + pid.replace("/", "_")
        store._store_and_validate_data(
            pid, path, checksum=algo_checksum, checksum_algorithm=algo
        )
    assert store._count("objects") == 3


def test_store_and_validate_data_with_incorrect_checksum(pids, store):
    """Check _store_and_validate_data does not store data objects when a bad checksum supplied."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        algo = "sha224"
        algo_checksum = "badChecksumValue"
        path = test_dir + pid.replace("/", "_")
        with pytest.raises(NonMatchingChecksum):
            store._store_and_validate_data(
                pid, path, checksum=algo_checksum, checksum_algorithm=algo
            )
    assert store._count(entity) == 0


def test_store_data_only_cid(pids, store):
    """Check _store_data_only returns correct id."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store._store_data_only(path)
        assert object_metadata.cid == pids[pid][store.algorithm]


def test_store_data_only_file_size(pids, store):
    """Check _store_data_only returns correct file size."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store._store_data_only(path)
        assert object_metadata.obj_size == pids[pid]["file_size_bytes"]


def test_store_data_only_hex_digests(pids, store):
    """Check _store_data_only generates a hex digests dictionary."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store._store_data_only(path)
        assert object_metadata.hex_digests.get("md5") == pids[pid]["md5"]
        assert object_metadata.hex_digests.get("sha1") == pids[pid]["sha1"]
        assert object_metadata.hex_digests.get("sha256") == pids[pid]["sha256"]
        assert object_metadata.hex_digests.get("sha384") == pids[pid]["sha384"]
        assert object_metadata.hex_digests.get("sha512") == pids[pid]["sha512"]


def test_move_and_get_checksums_id(pids, store):
    """Test _move_and_get_checksums returns correct id."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        (
            move_id,
            _,
            _,
        ) = store._move_and_get_checksums(pid, input_stream)
        input_stream.close()
        assert move_id == pids[pid][store.algorithm]


def test_move_and_get_checksums_file_size(pids, store):
    """Test _move_and_get_checksums returns correct file size."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        (
            _,
            tmp_file_size,
            _,
        ) = store._move_and_get_checksums(pid, input_stream)
        input_stream.close()
        assert tmp_file_size == pids[pid]["file_size_bytes"]


def test_move_and_get_checksums_hex_digests(pids, store):
    """Test _move_and_get_checksums returns correct hex digests."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
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


def test_move_and_get_checksums_does_not_store_duplicate(pids, store):
    """Test _move_and_get_checksums does not store duplicate objects."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        store._move_and_get_checksums(pid, input_stream)
        input_stream.close()
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        store._move_and_get_checksums(pid, input_stream)
        input_stream.close()
    assert store._count("objects") == 3


def test_move_and_get_checksums_raises_error_with_nonmatching_checksum(pids, store):
    """Test _move_and_get_checksums raises error when incorrect checksum supplied."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        with pytest.raises(NonMatchingChecksum):
            # pylint: disable=W0212
            store._move_and_get_checksums(
                pid,
                input_stream,
                checksum="nonmatchingchecksum",
                checksum_algorithm="sha256",
            )
            input_stream.close()
    assert store._count("objects") == 0


def test_move_and_get_checksums_incorrect_file_size(pids, store):
    """Test _move_and_get_checksums raises error with an incorrect file size."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        with pytest.raises(NonMatchingObjSize):
            path = test_dir + pid.replace("/", "_")
            input_stream = io.open(path, "rb")
            incorrect_file_size = 1000
            (_, _, _, _,) = store._move_and_get_checksums(
                pid, input_stream, file_size_to_validate=incorrect_file_size
            )
            input_stream.close()


def test_write_to_tmp_file_and_get_hex_digests_additional_algo(store):
    """Test _write...hex_digests returns correct hex digests with an additional algorithm."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    input_stream = io.open(path, "rb")
    checksum_algo = "sha3_256"
    checksum_correct = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    hex_digests, _, _ = store._write_to_tmp_file_and_get_hex_digests(
        input_stream, additional_algorithm=checksum_algo
    )
    input_stream.close()
    assert hex_digests.get("sha3_256") == checksum_correct


def test_write_to_tmp_file_and_get_hex_digests_checksum_algo(store):
    """Test _write...hex_digests returns correct hex digests when given a checksum_algorithm
    and checksum."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    input_stream = io.open(path, "rb")
    checksum_algo = "sha3_256"
    checksum_correct = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    hex_digests, _, _ = store._write_to_tmp_file_and_get_hex_digests(
        input_stream, checksum_algorithm=checksum_algo
    )
    input_stream.close()
    assert hex_digests.get("sha3_256") == checksum_correct


def test_write_to_tmp_file_and_get_hex_digests_checksum_and_additional_algo(store):
    """Test _write...hex_digests returns correct hex digests when an additional and
    checksum algorithm is provided."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    input_stream = io.open(path, "rb")
    additional_algo = "sha224"
    additional_algo_checksum_correct = (
        "9b3a96f434f3c894359193a63437ef86fbd5a1a1a6cc37f1d5013ac1"
    )
    checksum_algo = "sha3_256"
    checksum_correct = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    hex_digests, _, _ = store._write_to_tmp_file_and_get_hex_digests(
        input_stream,
        additional_algorithm=additional_algo,
        checksum_algorithm=checksum_algo,
    )
    input_stream.close()
    assert hex_digests.get("sha3_256") == checksum_correct
    assert hex_digests.get("sha224") == additional_algo_checksum_correct


def test_write_to_tmp_file_and_get_hex_digests_checksum_and_additional_algo_duplicate(
    store,
):
    """Test _write...hex_digests succeeds with duplicate algorithms (de-duplicates)."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    input_stream = io.open(path, "rb")
    additional_algo = "sha224"
    checksum_algo = "sha224"
    checksum_correct = "9b3a96f434f3c894359193a63437ef86fbd5a1a1a6cc37f1d5013ac1"
    hex_digests, _, _ = store._write_to_tmp_file_and_get_hex_digests(
        input_stream,
        additional_algorithm=additional_algo,
        checksum_algorithm=checksum_algo,
    )
    input_stream.close()
    assert hex_digests.get("sha224") == checksum_correct


def test_write_to_tmp_file_and_get_hex_digests_file_size(pids, store):
    """Test _write...hex_digests returns correct file size."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        _, _, tmp_file_size = store._write_to_tmp_file_and_get_hex_digests(input_stream)
        input_stream.close()
        assert tmp_file_size == pids[pid]["file_size_bytes"]


def test_write_to_tmp_file_and_get_hex_digests_hex_digests(pids, store):
    """Test _write...hex_digests returns correct hex digests."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        hex_digests, _, _ = store._write_to_tmp_file_and_get_hex_digests(input_stream)
        input_stream.close()
        assert hex_digests.get("md5") == pids[pid]["md5"]
        assert hex_digests.get("sha1") == pids[pid]["sha1"]
        assert hex_digests.get("sha256") == pids[pid]["sha256"]
        assert hex_digests.get("sha384") == pids[pid]["sha384"]
        assert hex_digests.get("sha512") == pids[pid]["sha512"]


def test_write_to_tmp_file_and_get_hex_digests_tmpfile_object(pids, store):
    """Test _write...hex_digests returns a tmp file successfully."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        _, tmp_file_name, _ = store._write_to_tmp_file_and_get_hex_digests(input_stream)
        input_stream.close()
        assert os.path.isfile(tmp_file_name) is True


def test_write_to_tmp_file_and_get_hex_digests_with_unsupported_algorithm(pids, store):
    """Test _write...hex_digests raises an exception when an unsupported algorithm supplied."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        algo = "md2"
        with pytest.raises(UnsupportedAlgorithm):
            _, _, _ = store._write_to_tmp_file_and_get_hex_digests(
                input_stream, additional_algorithm=algo
            )
        with pytest.raises(UnsupportedAlgorithm):
            _, _, _ = store._write_to_tmp_file_and_get_hex_digests(
                input_stream, checksum_algorithm=algo
            )
        input_stream.close()


def test_mktmpfile(store):
    """Test that _mktmpfile creates and returns a tmp file."""
    path = store.root / "doutest" / "tmp"
    store._create_path(path)
    tmp = store._mktmpfile(path)
    assert os.path.exists(tmp.name)


def test_store_hashstore_refs_files_(pids, store):
    """Test _store_hashstore_refs_files does not throw exception when successful."""
    for pid in pids.keys():
        cid = pids[pid][store.algorithm]
        store._store_hashstore_refs_files(pid, cid)
    assert store._count("pid") == 3
    assert store._count("cid") == 3


def test_store_hashstore_refs_files_pid_refs_file_exists(pids, store):
    """Test _store_hashstore_refs_file creates the expected pid reference file."""
    for pid in pids.keys():
        cid = pids[pid][store.algorithm]
        store._store_hashstore_refs_files(pid, cid)
        pid_refs_file_path = store._get_hashstore_pid_refs_path(pid)
        assert os.path.exists(pid_refs_file_path)


def test_store_hashstore_refs_file_cid_refs_file_exists(pids, store):
    """Test _store_hashstore_refs_file creates the cid reference file."""
    for pid in pids.keys():
        cid = pids[pid][store.algorithm]
        store._store_hashstore_refs_files(pid, cid)
        cid_refs_file_path = store._get_hashstore_cid_refs_path(cid)
        assert os.path.exists(cid_refs_file_path)


def test_store_hashstore_refs_file_pid_refs_file_content(pids, store):
    """Test _store_hashstore_refs_file created the pid reference file with the expected cid."""
    for pid in pids.keys():
        cid = pids[pid][store.algorithm]
        store._store_hashstore_refs_files(pid, cid)
        pid_refs_file_path = store._get_hashstore_pid_refs_path(pid)
        with open(pid_refs_file_path, "r", encoding="utf8") as f:
            pid_refs_cid = f.read()
        assert pid_refs_cid == cid


def test_store_hashstore_refs_file_cid_refs_file_content(pids, store):
    """Test _store_hashstore_refs_file creates the cid reference file successfully with pid
    tagged."""
    for pid in pids.keys():
        cid = pids[pid][store.algorithm]
        store._store_hashstore_refs_files(pid, cid)
        cid_refs_file_path = store._get_hashstore_cid_refs_path(cid)
        with open(cid_refs_file_path, "r", encoding="utf8") as f:
            pid_refs_cid = f.read().strip()
        assert pid_refs_cid == pid


def test_store_hashstore_refs_file_pid_refs_found_cid_refs_found(pids, store):
    """Test _store_hashstore_refs_file does not throw an exception when any refs file already exists
    and verifies the content, and does not double tag the cid refs file."""
    for pid in pids.keys():
        cid = pids[pid][store.algorithm]
        store._store_hashstore_refs_files(pid, cid)

        with pytest.raises(HashStoreRefsAlreadyExists):
            store.tag_object(pid, cid)

        cid_refs_file_path = store._get_hashstore_cid_refs_path(cid)
        line_count = 0
        with open(cid_refs_file_path, "r", encoding="utf8") as ref_file:
            for _line in ref_file:
                line_count += 1
        assert line_count == 1


def test_store_hashstore_refs_files_pid_refs_found_cid_refs_not_found(store, pids):
    """Test that _store_hashstore_refs_files throws an exception when pid refs file exists,
    contains a different cid, and is correctly referenced in the associated cid refs file"""
    for pid in pids.keys():
        cid = pids[pid][store.algorithm]
        store._store_hashstore_refs_files(pid, cid)

        with pytest.raises(PidRefsAlreadyExistsError):
            store._store_hashstore_refs_files(
                pid, "another_cid_value_that_is_not_found"
            )


def test_store_hashstore_refs_files_refs_not_found_cid_refs_found(store):
    """Test _store_hashstore_refs_files updates a cid reference file that already exists."""
    pid = "jtao.1700.1"
    cid = "94f9b6c88f1f458e410c30c351c6384ea42ac1b5ee1f8430d3e365e43b78a38a"
    # Tag object
    store._store_hashstore_refs_files(pid, cid)
    # Tag the cid with another pid
    additional_pid = "dou.test.1"
    store._store_hashstore_refs_files(additional_pid, cid)

    # Read cid file to confirm cid refs file contains the additional pid
    line_count = 0
    cid_ref_abs_path = store._get_hashstore_cid_refs_path(cid)
    with open(cid_ref_abs_path, "r", encoding="utf8") as f:
        for _, line in enumerate(f, start=1):
            value = line.strip()
            line_count += 1
            assert value == pid or value == additional_pid
    assert line_count == 2
    assert store._count("pid") == 2
    assert store._count("cid") == 1


def test_untag_object(pids, store):
    """Test _untag_object untags successfully."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = Path(test_dir + pid.replace("/", "_"))
        object_metadata = store.store_object(pid, path)
        cid = object_metadata.cid

        store._synchronize_referenced_locked_pids(pid)
        store._synchronize_object_locked_cids(cid)
        store._untag_object(pid, cid)
        store._release_reference_locked_pids(pid)
        store._release_object_locked_cids(cid)

        assert store._count("pid") == 0
        assert store._count("cid") == 0
    assert store._count("objects") == 3


def test_untag_object_pid_not_locked(pids, store):
    """Test _untag_object throws exception when pid is not locked"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = Path(test_dir + pid.replace("/", "_"))
        object_metadata = store.store_object(pid, path)
        cid = object_metadata.cid

        with pytest.raises(IdentifierNotLocked):
            store._untag_object(pid, cid)


def test_untag_object_cid_not_locked(pids, store):
    """Test _untag_object throws exception with cid is not locked"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = Path(test_dir + pid.replace("/", "_"))
        object_metadata = store.store_object(pid, path)
        cid = object_metadata.cid

        with pytest.raises(IdentifierNotLocked):
            store._synchronize_referenced_locked_pids(pid)
            store._untag_object(pid, cid)
            store._release_reference_locked_pids(pid)


def test_untag_object_orphan_pid_refs_file_found(store):
    """Test _untag_object removes an orphan pid refs file"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    object_metadata = store.store_object(pid, path)
    cid = object_metadata.cid

    # Remove cid refs file
    cid_refs_abs_path = store._get_hashstore_cid_refs_path(cid)
    os.remove(cid_refs_abs_path)

    with pytest.raises(OrphanPidRefsFileFound):
        store._find_object(pid)

    store._synchronize_referenced_locked_pids(pid)
    store._synchronize_object_locked_cids(cid)
    store._untag_object(pid, cid)
    store._release_reference_locked_pids(pid)
    store._release_object_locked_cids(cid)

    assert store._count("pid") == 0


def test_untag_object_orphan_refs_exist_but_data_object_not_found(store):
    """Test _untag_object removes orphaned pid and cid refs files"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    object_metadata = store.store_object(pid, path)
    cid = object_metadata.cid

    assert store._count("pid") == 1
    assert store._count("cid") == 1

    # Remove cid refs file
    data_obj_path = store._get_hashstore_data_object_path(cid)
    os.remove(data_obj_path)

    with pytest.raises(RefsFileExistsButCidObjMissing):
        store._find_object(pid)

    store._synchronize_referenced_locked_pids(pid)
    store._synchronize_object_locked_cids(cid)
    store._untag_object(pid, cid)
    store._release_reference_locked_pids(pid)
    store._release_object_locked_cids(cid)

    assert store._count("pid") == 0
    assert store._count("cid") == 0


def test_untag_object_refs_found_but_pid_not_in_cid_refs(store):
    """Test _untag_object removes pid refs file whose pid is not found in the cid refs file."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    pid_two = pid + ".dou"
    path = test_dir + pid
    object_metadata = store.store_object(pid, path)
    _object_metadata_two = store.store_object(pid_two, path)
    cid = object_metadata.cid

    assert store._count("pid") == 2
    assert store._count("cid") == 1

    # Remove pid from cid refs
    cid_refs_file = store._get_hashstore_cid_refs_path(cid)
    # First remove the pid
    store._update_refs_file(cid_refs_file, pid, "remove")

    with pytest.raises(PidNotFoundInCidRefsFile):
        store._find_object(pid)

    store._synchronize_referenced_locked_pids(pid)
    store._synchronize_object_locked_cids(cid)
    store._untag_object(pid, cid)
    store._release_reference_locked_pids(pid)
    store._release_object_locked_cids(cid)

    assert store._count("pid") == 1
    assert store._count("cid") == 1


def test_untag_object_pid_refs_file_does_not_exist(store):
    """Test _untag_object removes pid from cid refs file since the pid refs file does not exist,
    and does not delete the cid refs file because a reference is still present."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    pid_two = pid + ".dou"
    path = test_dir + pid
    object_metadata = store.store_object(pid, path)
    _object_metadata_two = store.store_object(pid_two, path)
    cid = object_metadata.cid

    assert store._count("pid") == 2
    assert store._count("cid") == 1

    # Remove pid from cid refs
    pid_refs_file = store._get_hashstore_pid_refs_path(pid)
    os.remove(pid_refs_file)

    with pytest.raises(PidRefsDoesNotExist):
        store._find_object(pid)

    store._synchronize_referenced_locked_pids(pid)
    store._synchronize_object_locked_cids(cid)
    store._untag_object(pid, cid)
    store._release_reference_locked_pids(pid)
    store._release_object_locked_cids(cid)

    assert store._count("pid") == 1
    assert store._count("cid") == 1


def test_untag_object_pid_refs_file_does_not_exist_and_cid_refs_is_empty(store):
    """Test '_untag_object' removes pid from cid refs file since the pid refs file does not exist,
    and deletes the cid refs file because it contains no more references (after the pid called
    with '_untag_object' is removed from the cid refs)."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    object_metadata = store.store_object(pid, path)
    cid = object_metadata.cid

    assert store._count("pid") == 1
    assert store._count("cid") == 1

    # Remove pid from cid refs
    pid_refs_file = store._get_hashstore_pid_refs_path(pid)
    os.remove(pid_refs_file)

    with pytest.raises(PidRefsDoesNotExist):
        store._find_object(pid)

    store._synchronize_referenced_locked_pids(pid)
    store._synchronize_object_locked_cids(cid)
    store._untag_object(pid, cid)
    store._release_reference_locked_pids(pid)
    store._release_object_locked_cids(cid)

    assert store._count("pid") == 0
    assert store._count("cid") == 0


def test_put_metadata_with_path(pids, store):
    """Test _put_metadata with path object for the path arg."""
    entity = "metadata"
    test_dir = "tests/testdata/"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        metadata_stored_path = store._put_metadata(syspath, pid, format_id)
        assert store._exists(entity, metadata_stored_path)
    assert store._count(entity) == 3


def test_put_metadata_with_string(pids, store):
    """Test_put metadata with string for the path arg."""
    entity = "metadata"
    test_dir = "tests/testdata/"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = str(Path(test_dir) / filename)
        metadata_stored_path = store._put_metadata(syspath, pid, format_id)
        assert store._exists(entity, metadata_stored_path)
    assert store._count(entity) == 3


def test_put_metadata_stored_path(pids, store):
    """Test put metadata returns correct path to the metadata stored."""
    test_dir = "tests/testdata/"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        metadata_document_name = store._computehash(pid + format_id)
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        metadata_stored_path = store._put_metadata(syspath, pid, metadata_document_name)

        # Manually calculate expected path
        metadata_directory = store._computehash(pid)
        rel_path = Path(*store._shard(metadata_directory))
        full_path = (
            store._get_store_path("metadata") / rel_path / metadata_document_name
        )
        assert metadata_stored_path == full_path


def test_mktmpmetadata(pids, store):
    """Test mktmpmetadata creates tmpFile."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        sys_stream = io.open(syspath, "rb")
        # pylint: disable=W0212
        tmp_name = store._mktmpmetadata(sys_stream)
        sys_stream.close()
        assert os.path.exists(tmp_name)


# Tests for FileHashStore Utility & Supporting Methods


def test_delete_marked_files(store):
    """Test that _delete_marked_files removes all items from a given list"""
    pid = "jtao.1700.1"
    cid = "94f9b6c88f1f458e410c30c351c6384ea42ac1b5ee1f8430d3e365e43b78a38a"
    # Tag object
    store._store_hashstore_refs_files(pid, cid)
    # Tag the cid with another pid
    additional_pid = "dou.test.1"
    store._store_hashstore_refs_files(additional_pid, cid)

    list_to_check = []
    pid_refs_path = store._get_hashstore_pid_refs_path(pid)
    store._mark_pid_refs_file_for_deletion(pid, list_to_check, pid_refs_path)
    pid_refs_path_two = store._get_hashstore_pid_refs_path(additional_pid)
    store._mark_pid_refs_file_for_deletion(pid, list_to_check, pid_refs_path_two)

    assert len(list_to_check) == 2

    store._delete_marked_files(list_to_check)

    assert not os.path.exists(list_to_check[0])
    assert not os.path.exists(list_to_check[1])


def test_delete_marked_files_empty_list_or_none(store):
    """Test that _delete_marked_files throws exception when supplied 'None' value - and does not
    throw any exception when provided with an empty list."""
    list_to_check = []
    store._delete_marked_files(list_to_check)

    with pytest.raises(ValueError):
        store._delete_marked_files(None)


def test_mark_pid_refs_file_for_deletion(store):
    """Test _mark_pid_refs_file_for_deletion renames a given path for deletion (adds '_delete' to
    the path name) and adds it to the given list."""
    pid = "dou.test.1"
    cid = "agoodcid"
    list_to_check = []
    store._store_hashstore_refs_files(pid, cid)
    pid_refs_path = store._get_hashstore_pid_refs_path(pid)

    store._mark_pid_refs_file_for_deletion(pid, list_to_check, pid_refs_path)

    assert len(list_to_check) == 1
    assert "_delete" in str(list_to_check[0])


def test_remove_pid_and_handle_cid_refs_deletion_multiple_cid_refs_contains_multi_pids(
    store,
):
    """Test _remove_pid_and_handle_cid_refs_deletion removes a pid from the cid refs file."""
    pid = "dou.test.1"
    pid_two = "dou.test.2"
    cid = "agoodcid"
    list_to_check = []
    store._store_hashstore_refs_files(pid, cid)
    store._store_hashstore_refs_files(pid_two, cid)

    cid_refs_path = store._get_hashstore_cid_refs_path(cid)
    store._remove_pid_and_handle_cid_refs_deletion(pid, list_to_check, cid_refs_path)

    assert store._is_string_in_refs_file(pid, cid_refs_path) is False
    assert store._count("cid") == 1
    assert len(list_to_check) == 0


def test_remove_pid_and_handle_cid_refs_deletion_cid_refs_empty(store):
    """Test _remove_pid_and_handle_cid_refs_deletion removes a pid from the cid refs file and
    deletes it when it is empty after removal."""
    pid = "dou.test.1"
    cid = "agoodcid"
    list_to_check = []
    store._store_hashstore_refs_files(pid, cid)

    cid_refs_path = store._get_hashstore_cid_refs_path(cid)
    store._remove_pid_and_handle_cid_refs_deletion(pid, list_to_check, cid_refs_path)
    delete_path = cid_refs_path.with_name(cid_refs_path.name + "_delete")

    assert not os.path.exists(cid_refs_path)
    assert os.path.exists(delete_path)
    assert len(list_to_check) == 1


def test_validate_and_check_cid_lock_non_matching_cid(store):
    """Test that _validate_and_check_cid_lock throws exception when cid is different"""
    pid = "dou.test.1"
    cid = "thegoodcid"
    cid_to_check = "thebadcid"

    with pytest.raises(ValueError):
        store._validate_and_check_cid_lock(pid, cid, cid_to_check)


def test_validate_and_check_cid_lock_identifier_not_locked(store):
    """Test that _validate_and_check_cid_lock throws exception when cid is not locked"""
    pid = "dou.test.1"
    cid = "thegoodcid"

    with pytest.raises(IdentifierNotLocked):
        store._validate_and_check_cid_lock(pid, cid, cid)


def test_write_refs_file_ref_type_cid(store):
    """Test that write_refs_file writes a reference file when given a 'cid' update_type."""
    tmp_root_path = store._get_store_path("refs") / "tmp"
    tmp_cid_refs_file = store._write_refs_file(tmp_root_path, "test_pid", "cid")
    assert os.path.exists(tmp_cid_refs_file)


def test_write_refs_file_ref_type_content_cid(pids, store):
    """Test that write_refs_file writes the expected content when given a 'cid' update_type."""
    for pid in pids.keys():
        tmp_root_path = store._get_store_path("refs") / "tmp"
        tmp_cid_refs_file = store._write_refs_file(tmp_root_path, pid, "cid")
        with open(tmp_cid_refs_file, "r", encoding="utf8") as f:
            cid_ref_file_pid = f.read()

        assert pid == cid_ref_file_pid.strip()


def test_write_refs_file_ref_type_pid(pids, store):
    """Test that write_pid_refs_file writes a reference file when given a 'pid' update_type."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        tmp_root_path = store._get_store_path("refs") / "tmp"
        tmp_pid_refs_file = store._write_refs_file(tmp_root_path, cid, "pid")
        assert os.path.exists(tmp_pid_refs_file)


def test_write_refs_file_ref_type_content_pid(pids, store):
    """Test that write_refs_file writes the expected content when given a 'pid' update_type"""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        tmp_root_path = store._get_store_path("refs") / "tmp"
        tmp_pid_refs_file = store._write_refs_file(tmp_root_path, cid, "pid")
        with open(tmp_pid_refs_file, "r", encoding="utf8") as f:
            pid_refs_cid = f.read()

        assert cid == pid_refs_cid


def test_update_refs_file_content(pids, store):
    """Test that update_refs_file updates the ref file as expected."""
    for pid in pids.keys():
        tmp_root_path = store._get_store_path("refs") / "tmp"
        tmp_cid_refs_file = store._write_refs_file(tmp_root_path, pid, "cid")
        pid_other = "dou.test.1"
        store._update_refs_file(tmp_cid_refs_file, pid_other, "add")

        with open(tmp_cid_refs_file, "r", encoding="utf8") as f:
            for _, line in enumerate(f, start=1):
                value = line.strip()
                assert value == pid or value == pid_other


def test_update_refs_file_content_multiple(pids, store):
    """Test that _update_refs_file adds multiple references successfully."""
    for pid in pids.keys():
        tmp_root_path = store._get_store_path("refs") / "tmp"
        tmp_cid_refs_file = store._write_refs_file(tmp_root_path, pid, "cid")

        cid_reference_list = [pid]
        for i in range(0, 5):
            store._update_refs_file(tmp_cid_refs_file, f"dou.test.{i}", "add")
            cid_reference_list.append(f"dou.test.{i}")

        line_count = 0
        with open(tmp_cid_refs_file, "r", encoding="utf8") as f:
            for _, line in enumerate(f, start=1):
                line_count += 1
                value = line.strip()
                assert value in cid_reference_list

        assert line_count == 6


def test_update_refs_file_deduplicates_pid_already_found(pids, store):
    """Test that _update_refs_file does not add a pid to a refs file that already
    contains the pid."""
    for pid in pids.keys():
        tmp_root_path = store._get_store_path("refs") / "tmp"
        tmp_cid_refs_file = store._write_refs_file(tmp_root_path, pid, "cid")
        # Exception should not be thrown
        store._update_refs_file(tmp_cid_refs_file, pid, "add")

        line_count = 0
        with open(tmp_cid_refs_file, "r", encoding="utf8") as ref_file:
            for _line in ref_file:
                line_count += 1
        assert line_count == 1


def test_update_refs_file_content_cid_refs_does_not_exist(pids, store):
    """Test that _update_refs_file throws exception if refs file doesn't exist."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store._get_hashstore_cid_refs_path(cid)
        with pytest.raises(FileNotFoundError):
            store._update_refs_file(cid_ref_abs_path, pid, "add")


def test_update_refs_file_remove(pids, store):
    """Test that _update_refs_file deletes the given pid from the ref file."""
    for pid in pids.keys():
        tmp_root_path = store._get_store_path("refs") / "tmp"
        tmp_cid_refs_file = store._write_refs_file(tmp_root_path, pid, "cid")

        pid_other = "dou.test.1"
        store._update_refs_file(tmp_cid_refs_file, pid_other, "add")
        store._update_refs_file(tmp_cid_refs_file, pid, "remove")

        with open(tmp_cid_refs_file, "r", encoding="utf8") as f:
            for _, line in enumerate(f, start=1):
                value = line.strip()
                assert value == pid_other


def test_update_refs_file_empty_file(pids, store):
    """Test that _update_refs_file leaves a file empty when removing the last pid."""
    for pid in pids.keys():
        tmp_root_path = store._get_store_path("refs") / "tmp"
        tmp_cid_refs_file = store._write_refs_file(tmp_root_path, pid, "cid")
        # First remove the pid
        store._update_refs_file(tmp_cid_refs_file, pid, "remove")

        assert os.path.exists(tmp_cid_refs_file)
        assert os.path.getsize(tmp_cid_refs_file) == 0


def test_is_string_in_refs_file(pids, store):
    """Test that _update_refs_file leaves a file empty when removing the last pid."""
    for pid in pids.keys():
        tmp_root_path = store._get_store_path("refs") / "tmp"
        tmp_cid_refs_file = store._write_refs_file(tmp_root_path, pid, "cid")

        cid_reference_list = [pid]
        for i in range(0, 5):
            store._update_refs_file(tmp_cid_refs_file, f"dou.test.{i}", "add")
            cid_reference_list.append(f"dou.test.{i}")

        assert store._is_string_in_refs_file("dou.test.2", tmp_cid_refs_file) is True


def test_verify_object_information(pids, store):
    """Test _verify_object_information succeeds given good arguments."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(data=path)
        hex_digests = object_metadata.hex_digests
        checksum = object_metadata.hex_digests.get(store.algorithm)
        checksum_algorithm = store.algorithm
        expected_file_size = object_metadata.obj_size
        store._verify_object_information(
            None,
            checksum,
            checksum_algorithm,
            None,
            hex_digests,
            None,
            expected_file_size,
            expected_file_size,
        )


def test_verify_object_information_incorrect_size(pids, store):
    """Test _verify_object_information throws exception when size is incorrect."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(data=path)
        hex_digests = object_metadata.hex_digests
        checksum = hex_digests.get(store.algorithm)
        checksum_algorithm = store.algorithm
        with pytest.raises(NonMatchingObjSize):
            store._verify_object_information(
                None,
                checksum,
                checksum_algorithm,
                None,
                hex_digests,
                None,
                1000,
                2000,
            )


def test_verify_object_information_incorrect_size_with_pid(pids, store):
    """Test _verify_object_information deletes the expected tmp file if obj size does
    not match and raises an exception."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(data=path)
        hex_digests = object_metadata.hex_digests
        checksum = object_metadata.hex_digests.get(store.algorithm)
        checksum_algorithm = store.algorithm
        expected_file_size = object_metadata.obj_size

        objects_tmp_folder = store.objects / "tmp"
        tmp_file = store._mktmpfile(objects_tmp_folder)
        assert os.path.isfile(tmp_file.name)
        with pytest.raises(NonMatchingObjSize):
            store._verify_object_information(
                "Test_Pid",
                checksum,
                checksum_algorithm,
                None,
                hex_digests,
                tmp_file.name,
                1000,
                expected_file_size,
            )
            assert not os.path.isfile(tmp_file.name)


def test_verify_object_information_missing_key_in_hex_digests_unsupported_algo(
    pids, store
):
    """Test _verify_object_information throws exception when algorithm is not found
    in hex digests and is not supported."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(data=path)
        checksum = object_metadata.hex_digests.get(store.algorithm)
        checksum_algorithm = "md10"
        expected_file_size = object_metadata.obj_size
        with pytest.raises(UnsupportedAlgorithm):
            store._verify_object_information(
                None,
                checksum,
                checksum_algorithm,
                "objects",
                object_metadata.hex_digests,
                None,
                expected_file_size,
                expected_file_size,
            )


def test_verify_object_information_missing_key_in_hex_digests_supported_algo(
    pids, store
):
    """Test _verify_object_information throws exception when algorithm is not found
    in hex digests but is supported, and the checksum calculated does not match."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(data=path)
        checksum = object_metadata.hex_digests.get(store.algorithm)
        checksum_algorithm = "blake2s"
        expected_file_size = object_metadata.obj_size
        with pytest.raises(NonMatchingChecksum):
            store._verify_object_information(
                None,
                checksum,
                checksum_algorithm,
                "objects",
                object_metadata.hex_digests,
                None,
                expected_file_size,
                expected_file_size,
            )


def test_verify_object_information_missing_key_in_hex_digests_matching_checksum(
    pids, store
):
    """Test _verify_object_information does not throw exception when algorithm is not found
    in hex digests but is supported, and the checksum calculated matches."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(data=path)
        checksum_algorithm = "blake2s"
        checksum = pids[pid][checksum_algorithm]
        expected_file_size = object_metadata.obj_size
        store._verify_object_information(
            None,
            checksum,
            checksum_algorithm,
            "objects",
            object_metadata.hex_digests,
            None,
            expected_file_size,
            expected_file_size,
        )


def test_verify_hashstore_references_pid_refs_file_missing(pids, store):
    """Test _verify_hashstore_references throws exception when pid refs file is missing."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        with pytest.raises(PidRefsFileNotFound):
            store._verify_hashstore_references(pid, cid)


def test_verify_hashstore_references_pid_refs_incorrect_cid(pids, store):
    """Test _verify_hashstore_references throws exception when pid refs file cid is incorrect."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        # Write the cid refs file and move it where it needs to be
        tmp_root_path = store._get_store_path("refs") / "tmp"
        tmp_cid_refs_file = store._write_refs_file(tmp_root_path, pid, "cid")
        cid_ref_abs_path = store._get_hashstore_cid_refs_path(cid)
        print(cid_ref_abs_path)
        store._create_path(os.path.dirname(cid_ref_abs_path))
        shutil.move(tmp_cid_refs_file, cid_ref_abs_path)
        # Write the pid refs file and move it where it needs to be with a bad cid
        pid_ref_abs_path = store._get_hashstore_pid_refs_path(pid)
        print(pid_ref_abs_path)
        store._create_path(os.path.dirname(pid_ref_abs_path))
        tmp_root_path = store._get_store_path("refs") / "tmp"
        tmp_pid_refs_file = store._write_refs_file(tmp_root_path, "bad_cid", "pid")
        shutil.move(tmp_pid_refs_file, pid_ref_abs_path)

        with pytest.raises(PidRefsContentError):
            store._verify_hashstore_references(pid, cid)


def test_verify_hashstore_references_cid_refs_file_missing(pids, store):
    """Test _verify_hashstore_references throws exception when cid refs file is missing."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        pid_ref_abs_path = store._get_hashstore_pid_refs_path(pid)
        store._create_path(os.path.dirname(pid_ref_abs_path))
        tmp_root_path = store._get_store_path("refs") / "tmp"
        tmp_pid_refs_file = store._write_refs_file(tmp_root_path, "bad_cid", "pid")
        shutil.move(tmp_pid_refs_file, pid_ref_abs_path)

        with pytest.raises(CidRefsFileNotFound):
            store._verify_hashstore_references(pid, cid)


def test_verify_hashstore_references_cid_refs_file_missing_pid(pids, store):
    """Test _verify_hashstore_references throws exception when cid refs file does not contain
    the expected pid."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        # Get a tmp cid refs file and write the wrong pid into it
        tmp_root_path = store._get_store_path("refs") / "tmp"
        tmp_cid_refs_file = store._write_refs_file(tmp_root_path, "bad pid", "cid")
        cid_ref_abs_path = store._get_hashstore_cid_refs_path(cid)
        store._create_path(os.path.dirname(cid_ref_abs_path))
        shutil.move(tmp_cid_refs_file, cid_ref_abs_path)
        # Now write the pid refs file, both cid and pid refs must be present
        pid_ref_abs_path = store._get_hashstore_pid_refs_path(pid)
        store._create_path(os.path.dirname(pid_ref_abs_path))
        tmp_root_path = store._get_store_path("refs") / "tmp"
        tmp_pid_refs_file = store._write_refs_file(tmp_root_path, cid, "pid")
        shutil.move(tmp_pid_refs_file, pid_ref_abs_path)

        with pytest.raises(CidRefsContentError):
            store._verify_hashstore_references(pid, cid)


def test_verify_hashstore_references_cid_refs_file_with_multiple_refs_missing_pid(
    pids, store
):
    """Test _verify_hashstore_references throws exception when cid refs file with multiple
    references does not contain the expected pid."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        # Write the wrong pid into a cid refs file and move it where it needs to be
        tmp_root_path = store._get_store_path("refs") / "tmp"
        tmp_cid_refs_file = store._write_refs_file(tmp_root_path, "bad pid", "cid")
        cid_ref_abs_path = store._get_hashstore_cid_refs_path(cid)
        store._create_path(os.path.dirname(cid_ref_abs_path))
        shutil.move(tmp_cid_refs_file, cid_ref_abs_path)
        # Now write the pid refs with expected values
        pid_ref_abs_path = store._get_hashstore_pid_refs_path(pid)
        store._create_path(os.path.dirname(pid_ref_abs_path))
        tmp_root_path = store._get_store_path("refs") / "tmp"
        tmp_pid_refs_file = store._write_refs_file(tmp_root_path, cid, "pid")
        shutil.move(tmp_pid_refs_file, pid_ref_abs_path)

        for i in range(0, 5):
            store._update_refs_file(cid_ref_abs_path, f"dou.test.{i}", "add")

        with pytest.raises(CidRefsContentError):
            store._verify_hashstore_references(pid, cid)


def test_delete_object_only(pids, store):
    """Test _delete_object successfully deletes only object."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid=None, data=path)
        store._delete_object_only(object_metadata.cid)
    assert store._count(entity) == 0


def test_delete_object_only_cid_refs_file_exists(pids, store):
    """Test _delete_object does not delete object if a cid refs file still exists."""
    test_dir = "tests/testdata/"
    entity = "objects"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        object_metadata = store.store_object(pid, path)
        _metadata_stored_path = store.store_metadata(pid, syspath, format_id)
        store._delete_object_only(object_metadata.cid)
    assert store._count(entity) == 3
    assert store._count("pid") == 3
    assert store._count("cid") == 3


def test_clean_algorithm(store):
    """Check that algorithm values get formatted as expected."""
    algorithm_underscore = "sha_256"
    algorithm_hyphen = "sha-256"
    algorithm_other_hyphen = "sha3-256"
    cleaned_algo_underscore = store._clean_algorithm(algorithm_underscore)
    cleaned_algo_hyphen = store._clean_algorithm(algorithm_hyphen)
    cleaned_algo_other_hyphen = store._clean_algorithm(algorithm_other_hyphen)
    assert cleaned_algo_underscore == "sha256"
    assert cleaned_algo_hyphen == "sha256"
    assert cleaned_algo_other_hyphen == "sha3_256"


def test_clean_algorithm_unsupported_algo(store):
    """Check that algorithm values get formatted as expected."""
    algorithm_unsupported = "mok22"
    with pytest.raises(UnsupportedAlgorithm):
        _ = store._clean_algorithm(algorithm_unsupported)


def test_computehash(pids, store):
    """Test to check computehash method."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        obj_stream = io.open(path, "rb")
        obj_sha256_hash = store._computehash(obj_stream, "sha256")
        obj_stream.close()
        assert pids[pid]["sha256"] == obj_sha256_hash


def test_shard(store):
    """Test shard creates list."""
    hash_id = "0d555ed77052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e"
    predefined_list = [
        "0d",
        "55",
        "5e",
        "d77052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e",
    ]
    sharded_list = store._shard(hash_id)
    assert predefined_list == sharded_list


def test_count(pids, store):
    """Check that count returns expected number of objects."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        path_string = test_dir + pid.replace("/", "_")
        store._store_and_validate_data(pid, path_string)
    assert store._count(entity) == 3


def test_exists_object_with_object_metadata_id(pids, store):
    """Test exists method with an absolute file path."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store._store_and_validate_data(pid, path)
        assert store._exists(entity, object_metadata.cid)


def test_exists_object_with_sharded_path(pids, store):
    """Test exists method with an absolute file path."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store._store_and_validate_data(pid, path)
        object_metadata_shard_path = os.path.join(*store._shard(object_metadata.cid))
        assert store._exists(entity, object_metadata_shard_path)


def test_exists_metadata_files_path(pids, store):
    """Test exists works as expected for metadata."""
    test_dir = "tests/testdata/"
    entity = "metadata"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        metadata_stored_path = store.store_metadata(pid, syspath, format_id)
        assert store._exists(entity, metadata_stored_path)


def test_exists_object_with_nonexistent_file(store):
    """Test exists method with a nonexistent file."""
    entity = "objects"
    non_existent_file = "tests/testdata/filedoesnotexist"
    does_not_exist = store._exists(entity, non_existent_file)
    assert does_not_exist is False


def test_open_objects(pids, store):
    """Test open returns a stream."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store._store_and_validate_data(pid, path)
        object_metadata_id = object_metadata.cid
        io_buffer = store._open(entity, object_metadata_id)
        assert isinstance(io_buffer, io.BufferedReader)
        io_buffer.close()


def test_private_delete_objects(pids, store):
    """Confirm _delete deletes for entity type 'objects'"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = Path(test_dir + pid.replace("/", "_"))
        object_metadata = store.store_object(pid, path)

        store._delete("objects", object_metadata.cid)
        assert store._count("objects") == 0


def test_private_delete_metadata(pids, store):
    """Confirm _delete deletes for entity type 'metadata'"""
    test_dir = "tests/testdata/"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        store.store_metadata(pid, syspath, format_id)

        # Manually calculate expected path
        metadata_directory = store._computehash(pid)
        metadata_document_name = store._computehash(pid + format_id)
        rel_path = Path(*store._shard(metadata_directory)) / metadata_document_name

        store._delete("metadata", rel_path)

        assert store._count("metadata") == 0


def test_private_delete_absolute_path(pids, store):
    """Confirm _delete deletes for absolute paths'"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = Path(test_dir + pid.replace("/", "_"))
        object_metadata = store.store_object(pid, path)

        cid_refs_path = store._get_hashstore_cid_refs_path(object_metadata.cid)
        store._delete("other", cid_refs_path)
        assert store._count("cid") == 0

        pid_refs_path = store._get_hashstore_pid_refs_path(pid)
        store._delete("other", pid_refs_path)
        assert store._count("pid") == 0


def test_create_path(pids, store):
    """Test makepath creates folder successfully."""
    for pid in pids:
        root_directory = store.root
        pid_hex_digest_directory = pids[pid]["metadata_cid"][:2]
        pid_directory = root_directory / pid_hex_digest_directory
        store._create_path(pid_directory)
        assert os.path.isdir(pid_directory)


def test_get_store_path_object(store):
    """Check get_store_path for object path."""
    # pylint: disable=W0212
    path_objects = store._get_store_path("objects")
    path_objects_string = str(path_objects)
    assert path_objects_string.endswith("/metacat/hashstore/objects")


def test_get_store_path_metadata(store):
    """Check get_store_path for metadata path."""
    # pylint: disable=W0212
    path_metadata = store._get_store_path("metadata")
    path_metadata_string = str(path_metadata)
    assert path_metadata_string.endswith("/metacat/hashstore/metadata")


def test_get_store_path_refs(store):
    """Check get_store_path for refs path."""
    # pylint: disable=W0212
    path_metadata = store._get_store_path("refs")
    path_metadata_string = str(path_metadata)
    assert path_metadata_string.endswith("/metacat/hashstore/refs")


def test_get_hashstore_data_object_path_file_does_not_exist(store):
    """Test _get_hashstore_data_object_path returns None when object does not exist."""
    test_path = "tests/testdata/helloworld.txt"
    with pytest.raises(FileNotFoundError):
        store._get_hashstore_data_object_path(test_path)


def test_get_hashstore_data_object_path_with_object_id(store, pids):
    """Test _get_hashstore_data_object_path returns absolute path given an object id."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store._store_and_validate_data(pid, path)
        obj_abs_path = store._get_hashstore_data_object_path(object_metadata.cid)
        assert os.path.exists(obj_abs_path)


def test_get_hashstore_metadata_path_absolute_path(store, pids):
    """Test _get_hashstore_metadata_path returns absolute path given a metadata id."""
    test_dir = "tests/testdata/"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        metadata_stored_path = store.store_metadata(pid, syspath, format_id)
        metadata_abs_path = store._get_hashstore_metadata_path(metadata_stored_path)
        assert os.path.exists(metadata_abs_path)


def test_get_hashstore_metadata_path_relative_path(pids, store):
    """Confirm resolve path returns correct metadata path."""
    test_dir = "tests/testdata/"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        _metadata_stored_path = store.store_metadata(pid, syspath, format_id)

        metadata_directory = store._computehash(pid)
        metadata_document_name = store._computehash(pid + format_id)
        rel_path = Path(*store._shard(metadata_directory))
        full_path_without_dir = Path(rel_path) / metadata_document_name

        metadata_resolved_path = store._get_hashstore_metadata_path(
            full_path_without_dir
        )
        calculated_metadata_path = store.metadata / rel_path / metadata_document_name

        assert Path(calculated_metadata_path) == metadata_resolved_path


def test_get_hashstore_pid_refs_path(pids, store):
    """Confirm resolve path returns correct object pid refs path"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = Path(test_dir + pid.replace("/", "_"))
        _object_metadata = store.store_object(pid, path)

        resolved_pid_ref_abs_path = store._get_hashstore_pid_refs_path(pid)
        pid_refs_metadata_hashid = store._computehash(pid)
        calculated_pid_ref_path = store.pids / Path(
            *store._shard(pid_refs_metadata_hashid)
        )

        assert resolved_pid_ref_abs_path == Path(calculated_pid_ref_path)


def test_get_hashstore_cid_refs_path(pids, store):
    """Confirm resolve path returns correct object pid refs path"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = Path(test_dir + pid.replace("/", "_"))
        object_metadata = store.store_object(pid, path)
        cid = object_metadata.cid

        resolved_cid_ref_abs_path = store._get_hashstore_cid_refs_path(cid)
        calculated_cid_ref_path = store.cids / Path(*store._shard(cid))

        assert resolved_cid_ref_abs_path == Path(calculated_cid_ref_path)


def test_check_string(store):
    """Confirm that an exception is raised when a string is None, empty or contains an illegal
    character (ex. tabs or new lines)"""
    empty_pid_with_spaces = "   "
    with pytest.raises(ValueError):
        store._check_string(empty_pid_with_spaces, "empty_pid_with_spaces")

    none_value = None
    with pytest.raises(ValueError):
        store._check_string(none_value, "none_value")

    new_line = "\n"
    with pytest.raises(ValueError):
        store._check_string(new_line, "new_line")

    new_line_with_other_chars = "hello \n"
    with pytest.raises(ValueError):
        store._check_string(new_line_with_other_chars, "new_line_with_other_chars")

    tab_line = "\t"
    with pytest.raises(ValueError):
        store._check_string(tab_line, "tab_line")


def test_cast_to_bytes(store):
    """Test _to_bytes returns bytes."""
    string = "teststring"
    # pylint: disable=W0212
    string_bytes = store._cast_to_bytes(string)
    assert isinstance(string_bytes, bytes)


def test_stream_reads_file(pids):
    """Test that a stream can read a file and yield its contents."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path_string = test_dir + pid.replace("/", "_")
        obj_stream = Stream(path_string)
        hashobj = hashlib.new("sha256")
        for data in obj_stream:
            hashobj.update(data)
        obj_stream.close()
        hex_digest = hashobj.hexdigest()
        assert pids[pid]["sha256"] == hex_digest


def test_stream_reads_path_object(pids):
    """Test that a stream can read a file-like object and yield its contents."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = Path(test_dir + pid.replace("/", "_"))
        obj_stream = Stream(path)
        hash_obj = hashlib.new("sha256")
        for data in obj_stream:
            hash_obj.update(data)
        obj_stream.close()
        hex_digest = hash_obj.hexdigest()
        assert pids[pid]["sha256"] == hex_digest


def test_stream_returns_to_original_position_on_close(pids):
    """Test that a stream returns to its original position after closing the file."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path_string = test_dir + pid.replace("/", "_")
        input_stream = io.open(path_string, "rb")
        input_stream.seek(5)
        hashobj = hashlib.new("sha256")
        obj_stream = Stream(input_stream)
        for data in obj_stream:
            hashobj.update(data)
        obj_stream.close()
        assert input_stream.tell() == 5
        input_stream.close()


# noinspection PyTypeChecker
def test_stream_raises_error_for_invalid_object():
    """Test that a stream raises ValueError for an invalid input object."""
    with pytest.raises(ValueError):
        Stream(1234)


def test_objectmetadata():
    """Test ObjectMetadata class returns correct values via dot notation."""
    pid = "hashstore"
    ab_id = "hashstoretest"
    obj_size = 1234
    hex_digest_dict = {
        "md5": "md5value",
        "sha1": "sha1value",
        "sha224": "sha224value",
        "sha256": "sha256value",
        "sha512": "sha512value",
    }
    object_metadata = ObjectMetadata(pid, ab_id, obj_size, hex_digest_dict)
    assert object_metadata.pid == pid
    assert object_metadata.cid == ab_id
    assert object_metadata.obj_size == obj_size
    assert object_metadata.hex_digests.get("md5") == hex_digest_dict["md5"]
    assert object_metadata.hex_digests.get("sha1") == hex_digest_dict["sha1"]
    assert object_metadata.hex_digests.get("sha224") == hex_digest_dict["sha224"]
    assert object_metadata.hex_digests.get("sha256") == hex_digest_dict["sha256"]
    assert object_metadata.hex_digests.get("sha512") == hex_digest_dict["sha512"]
