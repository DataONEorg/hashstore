"""Test module for FileHashStore HashStore interface methods"""
import io
import os
from pathlib import Path
from threading import Thread
import random
import threading
import time
import pytest

# Define a mark to be used to label slow tests
slow_test = pytest.mark.skipif(
    "not config.getoption('--run-slow')",
    reason="Only run when --run-slow is given",
)


def test_pids_length(pids):
    """Ensure test harness pids are present."""
    assert len(pids) == 3


def test_store_address_length(pids, store):
    """Test store object object_cid length is 64 characters."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)
        object_cid = object_metadata.id
        assert len(object_cid) == 64


def test_store_object(pids, store):
    """Test store object."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        path = Path(test_dir + pid.replace("/", "_"))
        object_metadata = store.store_object(pid, path)
        assert object_metadata.id == pids[pid][store.algorithm]
    assert store.count(entity) == 3


def test_store_object_files_path(pids, store):
    """Test store object when given a path."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        path = Path(test_dir + pid.replace("/", "_"))
        _object_metadata = store.store_object(pid, path)
        assert store.exists(entity, pids[pid][store.algorithm])
    assert store.count(entity) == 3


def test_store_object_files_string(pids, store):
    """Test store object when given a string."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        path_string = test_dir + pid.replace("/", "_")
        _object_metadata = store.store_object(pid, path_string)
        assert store.exists(entity, pids[pid][store.algorithm])
    assert store.count(entity) == 3


def test_store_object_files_input_stream(pids, store):
    """Test store object given an input stream."""
    test_dir = "tests/testdata/"
    entity = "objects"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        _object_metadata = store.store_object(pid, input_stream)
        input_stream.close()
        assert store.exists(entity, pids[pid][store.algorithm])
    assert store.count(entity) == 3


def test_store_object_id(pids, store):
    """Test store object returns expected id."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)
        assert object_metadata.id == pids[pid][store.algorithm]


def test_store_object_obj_size(pids, store):
    """Test store object returns expected file size."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)
        object_size = object_metadata.obj_size
        assert object_size == pids[pid]["file_size_bytes"]


def test_store_object_hex_digests(pids, store):
    """Test store object returns expected hex digests dictionary."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)
        assert object_metadata.hex_digests.get("md5") == pids[pid]["md5"]
        assert object_metadata.hex_digests.get("sha1") == pids[pid]["sha1"]
        assert object_metadata.hex_digests.get("sha256") == pids[pid]["sha256"]
        assert object_metadata.hex_digests.get("sha384") == pids[pid]["sha384"]
        assert object_metadata.hex_digests.get("sha512") == pids[pid]["sha512"]


def test_store_object_pid_empty(store):
    """Test store object raises error when supplied with empty pid string."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    with pytest.raises(ValueError):
        store.store_object("", path)


def test_store_object_pid_empty_spaces(store):
    """Test store object raises error when supplied with empty space character."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    with pytest.raises(ValueError):
        store.store_object(" ", path)


def test_store_object_pid_none(store):
    """Test store object raises error when supplied with 'None' pid."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    with pytest.raises(ValueError):
        store.store_object(None, path)


def test_store_object_data_incorrect_type_none(store):
    """Test store object raises error when data is 'None'."""
    pid = "jtao.1700.1"
    path = None
    with pytest.raises(TypeError):
        store.store_object(pid, path)


def test_store_object_data_incorrect_type_empty(store):
    """Test store object raises error when data is an empty string."""
    pid = "jtao.1700.1"
    path = ""
    with pytest.raises(TypeError):
        store.store_object(pid, path)


def test_store_object_data_incorrect_type_empty_spaces(store):
    """Test store object raises error when data is an empty string with spaces."""
    pid = "jtao.1700.1"
    path = "   "
    with pytest.raises(TypeError):
        store.store_object(pid, path)


def test_store_object_additional_algorithm_invalid(store):
    """Test store object raises error when supplied with unsupported algorithm."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_not_in_list = "abc"
    with pytest.raises(ValueError, match="Algorithm not supported"):
        store.store_object(pid, path, algorithm_not_in_list)


def test_store_object_additional_algorithm_hyphen_uppercase(pids, store):
    """Test store object formats algorithm in uppercase."""
    test_dir = "tests/testdata/"
    entity = "objects"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_with_hyphen_and_upper = "SHA-384"
    object_metadata = store.store_object(pid, path, algorithm_with_hyphen_and_upper)
    sha256_cid = object_metadata.hex_digests.get("sha384")
    assert sha256_cid == pids[pid]["sha384"]
    assert store.exists(entity, pids[pid][store.algorithm])


def test_store_object_additional_algorithm_hyphen_lowercase(pids, store):
    """Test store object with additional algorithm in lowercase."""
    test_dir = "tests/testdata/"
    entity = "objects"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_other = "sha3-256"
    object_metadata = store.store_object(pid, path, algorithm_other)
    additional_sha3_256_hex_digest = object_metadata.hex_digests.get("sha3_256")
    sha3_256_checksum = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    assert additional_sha3_256_hex_digest == sha3_256_checksum
    assert store.exists(entity, pids[pid][store.algorithm])


def test_store_object_additional_algorithm_underscore(pids, store):
    """Test store object with additional algorithm with underscore."""
    test_dir = "tests/testdata/"
    entity = "objects"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_other = "sha3_256"
    object_metadata = store.store_object(pid, path, algorithm_other)
    additional_sha3_256_hex_digest = object_metadata.hex_digests.get("sha3_256")
    sha3_256_checksum = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    assert additional_sha3_256_hex_digest == sha3_256_checksum
    assert store.exists(entity, pids[pid][store.algorithm])


def test_store_object_checksum_correct(store):
    """Test store object successfully stores with good checksum."""
    test_dir = "tests/testdata/"
    entity = "objects"
    pid = "jtao.1700.1"
    path = test_dir + pid
    checksum_algo = "sha3_256"
    checksum_correct = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    _object_metadata = store.store_object(
        pid, path, checksum=checksum_correct, checksum_algorithm=checksum_algo
    )
    assert store.count(entity) == 1


def test_store_object_checksum_correct_and_additional_algo(store):
    """Test store object successfully stores with good checksum and same additional algorithm."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_additional = "sha224"
    sha224_additional_checksum = (
        "9b3a96f434f3c894359193a63437ef86fbd5a1a1a6cc37f1d5013ac1"
    )
    algorithm_checksum = "sha3_256"
    checksum_correct = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    object_metadata = store.store_object(
        pid,
        path,
        additional_algorithm=algorithm_additional,
        checksum=checksum_correct,
        checksum_algorithm=algorithm_checksum,
    )
    assert object_metadata.hex_digests.get("sha224") == sha224_additional_checksum
    assert object_metadata.hex_digests.get("sha3_256") == checksum_correct


def test_store_object_checksum_correct_and_additional_algo_duplicate(store):
    """Test store object successfully stores with good checksum and same additional algorithm."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_additional = "sha3_256"
    algorithm_checksum = "sha3_256"
    checksum_correct = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    object_metadata = store.store_object(
        pid,
        path,
        additional_algorithm=algorithm_additional,
        checksum=checksum_correct,
        checksum_algorithm=algorithm_checksum,
    )
    assert object_metadata.hex_digests.get("sha3_256") == checksum_correct


def test_store_object_checksum_algorithm_empty(store):
    """Test store object raises error when checksum supplied with no checksum_algorithm."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    checksum_correct = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    with pytest.raises(ValueError):
        store.store_object(pid, path, checksum=checksum_correct, checksum_algorithm="")


def test_store_object_checksum_empty(store):
    """Test store object raises error when checksum_algorithm supplied with empty checksum."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    checksum_algorithm = "sha3_256"
    with pytest.raises(ValueError):
        store.store_object(
            pid, path, checksum="", checksum_algorithm=checksum_algorithm
        )


def test_store_object_checksum_empty_spaces(store):
    """Test store object raises error when checksum_algorithm supplied and checksum is empty
    with spaces."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    checksum_algorithm = "sha3_256"
    with pytest.raises(ValueError):
        store.store_object(
            pid, path, checksum="  ", checksum_algorithm=checksum_algorithm
        )


def test_store_object_checksum_algorithm_empty_spaces(store):
    """Test store object raises error when checksum supplied with no checksum_algorithm."""
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
    """Test store object raises error when supplied with bad checksum."""
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


def test_store_object_duplicate_raises_error(pids, store):
    """Test store duplicate object throws FileExistsError."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    entity = "objects"
    # Store first blob
    _object_metadata_one = store.store_object(pid, path)
    # Store second blob
    with pytest.raises(FileExistsError):
        _object_metadata_two = store.store_object(pid, path)
    assert store.count(entity) == 1
    assert store.exists(entity, pids[pid][store.algorithm])


def test_store_object_with_obj_file_size(store, pids):
    """Test store object with correct file sizes."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        obj_file_size = pids[pid]["file_size_bytes"]
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(
            pid, path, expected_object_size=obj_file_size
        )
        object_size = object_metadata.obj_size
        assert object_size == obj_file_size


def test_store_object_with_obj_file_size_incorrect(store, pids):
    """Test store object throws exception with incorrect file size."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        obj_file_size = 1234
        path = test_dir + pid.replace("/", "_")
        with pytest.raises(ValueError):
            store.store_object(pid, path, expected_object_size=obj_file_size)


def test_store_object_with_obj_file_size_non_integer(store, pids):
    """Test store object throws exception with a non integer value as the file size."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        obj_file_size = "Bob"
        path = test_dir + pid.replace("/", "_")
        with pytest.raises(TypeError):
            store.store_object(pid, path, expected_object_size=obj_file_size)


def test_store_object_with_obj_file_size_zero(store, pids):
    """Test store object throws exception with zero as the file size."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        obj_file_size = 0
        path = test_dir + pid.replace("/", "_")
        with pytest.raises(ValueError):
            store.store_object(pid, path, expected_object_size=obj_file_size)


def test_store_object_duplicates_threads(pids, store):
    """Test store object thread lock."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    entity = "objects"

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
    assert store.count(entity) == 1
    assert store.exists(entity, pids[pid][store.algorithm])
    assert file_exists_error_flag


@slow_test
def test_store_object_interrupt_process(store):
    """Test that tmp file created when storing a large object (2GB) and
    interrupting the process is cleaned up.
    """
    file_size = 2 * 1024 * 1024 * 1024  # 2GB
    file_path = store.root + "random_file_2.bin"

    pid = "Testpid"
    # Generate a random file with the specified size
    with open(file_path, "wb") as file:
        remaining_bytes = file_size
        buffer_size = 1024 * 1024  # 1MB buffer size (adjust as needed)

        while remaining_bytes > 0:
            # Generate random data for the buffer
            buffer = bytearray(random.getrandbits(8) for _ in range(buffer_size))
            # Write the buffer to the file
            bytes_to_write = min(buffer_size, remaining_bytes)
            file.write(buffer[:bytes_to_write])
            remaining_bytes -= bytes_to_write

    interrupt_flag = False

    def store_object_wrapper(pid, path):
        print(store.root)
        while not interrupt_flag:
            store.store_object(pid, path)  # Call store_object inside the thread

    # Create/start the thread
    thread = threading.Thread(target=store_object_wrapper, args=(pid, file_path))
    thread.start()

    # Sleep for 5 seconds to let the thread run
    time.sleep(5)

    # Interrupt the thread
    interrupt_flag = True

    # Wait for the thread to finish
    thread.join()

    # Confirm no tmp objects found in objects/tmp directory
    assert len(os.listdir(store.root + "/objects/tmp")) == 0


@slow_test
def test_store_object_large_file(store):
    """Test storing a large object (1GB). This test has also been executed with
    a 4GB file and the test classes succeeded locally in 296.85s (0:04:56)
    """
    # file_size = 4 * 1024 * 1024 * 1024  # 4GB
    file_size = 1024 * 1024 * 1024  # 1GB
    file_path = store.root + "random_file.bin"
    # Generate a random file with the specified size
    with open(file_path, "wb") as file:
        remaining_bytes = file_size
        buffer_size = 1024 * 1024  # 1MB buffer size (adjust as needed)

        while remaining_bytes > 0:
            # Generate random data for the buffer
            buffer = bytearray(random.getrandbits(8) for _ in range(buffer_size))
            # Write the buffer to the file
            bytes_to_write = min(buffer_size, remaining_bytes)
            file.write(buffer[:bytes_to_write])
            remaining_bytes -= bytes_to_write
    # Store object
    pid = "testfile_filehashstore"
    object_metadata = store.store_object(pid, file_path)
    object_metadata_id = object_metadata.id
    assert object_metadata_id == object_metadata.hex_digests.get("sha256")


@slow_test
def test_store_object_sparse_large_file(store):
    """Test storing a large object (4GB) via sparse file. This test has also been
    executed with a 10GB file and the test classes succeeded locally in 117.03s (0:01:57).
    """
    # file_size = 10 * 1024 * 1024 * 1024  # 10GB
    file_size = 4 * 1024 * 1024 * 1024  # 4GB
    file_path = store.root + "random_file.bin"
    # Generate a random file with the specified size
    with open(file_path, "wb") as file:
        file.seek(file_size - 1)
        file.write(b"\0")
    # Store object
    pid = "testfile_filehashstore"
    object_metadata = store.store_object(pid, file_path)
    object_metadata_id = object_metadata.id
    assert object_metadata_id == object_metadata.hex_digests.get("sha256")


def test_tag_object(pids, store):
    """Test tag object returns boolean."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)
        object_tagged = store.tag_object(pid, object_metadata.id)
        assert object_tagged


def test_tag_object_pid_refs_file(pids, store):
    """Test tag object creates the pid reference file."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)
        store.tag_object(pid, object_metadata.id)
        pid_refs_file_path = store.get_refs_abs_path("pid", pid)
        assert os.path.exists(pid_refs_file_path)


def test_tag_object_pid_refs_file_exists(pids, store):
    """Test tag object throws exception when pid refs file already exists."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)
        cid = object_metadata.id
        store.tag_object(pid, cid)
        pid_refs_file_path = store.get_refs_abs_path("pid", pid)
        assert os.path.exists(pid_refs_file_path)
        cid_refs_file_path = store.get_refs_abs_path("cid", cid)
        assert os.path.exists(cid_refs_file_path)
        with pytest.raises(FileExistsError):
            store.tag_object(pid, cid)


def test_tag_object_pid_refs_file_content(pids, store):
    """Test tag object creates the pid reference file contains the correct cid."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)
        store.tag_object(pid, object_metadata.id)
        pid_refs_file_path = store.get_refs_abs_path("pid", pid)
        with open(pid_refs_file_path, "r", encoding="utf8") as f:
            pid_refs_cid = f.read()
        assert pid_refs_cid == object_metadata.id


def test_tag_object_cid_refs_file(pids, store):
    """Test tag object creates the cid reference file."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)
        cid = object_metadata.id
        store.tag_object(pid, object_metadata.id)
        cid_refs_file_path = store.get_refs_abs_path("cid", cid)
        assert os.path.exists(cid_refs_file_path)


def test_tag_object_cid_refs_file_content(pids, store):
    """Test tag object tags cid reference file successfully with pid."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)
        store.tag_object(pid, object_metadata.id)
        cid_refs_file_path = store.get_refs_abs_path("cid", object_metadata.id)
        with open(cid_refs_file_path, "r", encoding="utf8") as f:
            pid_refs_cid = f.read().strip()
        assert pid_refs_cid == pid


def test_tag_object_cid_refs_file_exists(pids, store):
    """Test tag object raises exception when trying to add another cid to an
    existing pid reference file and that a cid reference file is not created."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)
        store.tag_object(pid, object_metadata.id)
        another_cid = "dou.test.1"
        with pytest.raises(FileExistsError):
            store.tag_object(pid, another_cid)

        second_cid_hash = store.get_refs_abs_path("cid", another_cid)
        assert not os.path.exists(second_cid_hash)


def test_find_object(pids, store):
    """Test find object returns the correct content identifier (cid)."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)
        store.tag_object(pid, object_metadata.id)
        cid = store.find_object(pid)
        assert cid == object_metadata.hex_digests.get("sha256")


def test_find_object_pid_object_does_not_exist(store):
    """Test find object throws exception when object doesn't exist."""
    with pytest.raises(FileNotFoundError):
        store.find_object("dou.test.1")


def test_find_object_pid_none(store):
    """Test find object throws exception when pid is None."""
    with pytest.raises(ValueError):
        store.find_object(None)


def test_find_object_pid_empty(store):
    """Test find object throws exception when pid is empty."""
    with pytest.raises(ValueError):
        store.find_object("")


def test_store_metadata(pids, store):
    """Test store metadata."""
    test_dir = "tests/testdata/"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        metadata_cid = store.store_metadata(pid, syspath, format_id)
        assert metadata_cid == pids[pid]["metadata_cid"]


def test_store_metadata_default_format_id(pids, store):
    """Test store metadata returns expected id when storing with default format_id."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        metadata_cid = store.store_metadata(pid, syspath)
        assert metadata_cid == pids[pid]["metadata_cid"]


def test_store_metadata_files_path(pids, store):
    """Test store metadata with path."""
    test_dir = "tests/testdata/"
    entity = "metadata"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        metadata_cid = store.store_metadata(pid, syspath, format_id)
        assert store.exists(entity, metadata_cid)
        assert metadata_cid == pids[pid]["metadata_cid"]
    assert store.count(entity) == 3


def test_store_metadata_files_string(pids, store):
    """Test store metadata with string."""
    test_dir = "tests/testdata/"
    entity = "metadata"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath_string = str(Path(test_dir) / filename)
        metadata_cid = store.store_metadata(pid, syspath_string, format_id)
        assert store.exists(entity, metadata_cid)
    assert store.count(entity) == 3


def test_store_metadata_files_input_stream(pids, store):
    """Test store metadata with an input stream to metadata."""
    test_dir = "tests/testdata/"
    entity = "metadata"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath_string = str(Path(test_dir) / filename)
        syspath_stream = io.open(syspath_string, "rb")
        _metadata_cid = store.store_metadata(pid, syspath_stream, format_id)
        syspath_stream.close()
    assert store.count(entity) == 3


def test_store_metadata_pid_empty(store):
    """Test store metadata raises error with empty string."""
    test_dir = "tests/testdata/"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    pid = ""
    filename = pid.replace("/", "_") + ".xml"
    syspath_string = str(Path(test_dir) / filename)
    with pytest.raises(ValueError):
        store.store_metadata(pid, syspath_string, format_id)


def test_store_metadata_pid_empty_spaces(store):
    """Test store metadata raises error with empty spaces."""
    test_dir = "tests/testdata/"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    pid = "   "
    filename = pid.replace("/", "_") + ".xml"
    syspath_string = str(Path(test_dir) / filename)
    with pytest.raises(ValueError):
        store.store_metadata(pid, syspath_string, format_id)


def test_store_metadata_pid_format_id_spaces(store):
    """Test store metadata raises error with empty spaces."""
    test_dir = "tests/testdata/"
    format_id = "       "
    pid = "jtao.1700.1"
    filename = pid.replace("/", "_") + ".xml"
    syspath_string = str(Path(test_dir) / filename)
    with pytest.raises(ValueError):
        store.store_metadata(pid, syspath_string, format_id)


def test_store_metadata_metadata_empty(store):
    """Test store metadata raises error with empty metadata string."""
    pid = "jtao.1700.1"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    syspath_string = "   "
    with pytest.raises(TypeError):
        store.store_metadata(pid, syspath_string, format_id)


def test_store_metadata_metadata_none(store):
    """Test store metadata raises error with empty None metadata."""
    pid = "jtao.1700.1"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    syspath_string = None
    with pytest.raises(TypeError):
        store.store_metadata(pid, syspath_string, format_id)


def test_store_metadata_metadata_cid(pids, store):
    """Test store metadata returns expected metadata_cid."""
    test_dir = "tests/testdata/"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        _object_metadata = store.store_object(pid, path)
        metadata_cid = store.store_metadata(pid, syspath, format_id)
        assert metadata_cid == pids[pid]["metadata_cid"]


def test_store_metadata_thread_lock(store):
    """Test store metadata thread lock."""
    test_dir = "tests/testdata/"
    entity = "metadata"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    pid = "jtao.1700.1"
    path = test_dir + pid
    filename = pid + ".xml"
    syspath = Path(test_dir) / filename
    _object_metadata = store.store_object(pid, path)
    store.store_metadata(pid, syspath, format_id)
    # Start threads
    thread1 = Thread(target=store.store_metadata, args=(pid, syspath, format_id))
    thread2 = Thread(target=store.store_metadata, args=(pid, syspath, format_id))
    thread3 = Thread(target=store.store_metadata, args=(pid, syspath, format_id))
    thread4 = Thread(target=store.store_metadata, args=(pid, syspath, format_id))
    thread1.start()
    thread2.start()
    thread3.start()
    thread4.start()
    thread1.join()
    thread2.join()
    thread3.join()
    thread4.join()
    assert store.count(entity) == 1


def test_retrieve_object(pids, store):
    """Test retrieve_object returns correct object data."""
    test_dir = "tests/testdata/"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        object_metadata = store.store_object(pid, path)
        store.tag_object(pid, object_metadata.id)
        store.store_metadata(pid, syspath, format_id)
        obj_stream = store.retrieve_object(pid)
        sha256_hex = store.computehash(obj_stream)
        obj_stream.close()
        assert sha256_hex == object_metadata.hex_digests.get("sha256")


def test_retrieve_object_pid_empty(store):
    """Test retrieve_object raises error when supplied with empty pid."""
    pid = "   "
    with pytest.raises(ValueError):
        store.retrieve_object(pid)


def test_retrieve_object_pid_invalid(store):
    """Test retrieve_object raises error when supplied with bad pid."""
    pid = "jtao.1700.1"
    pid_does_not_exist = pid + "test"
    with pytest.raises(FileNotFoundError):
        store.retrieve_object(pid_does_not_exist)


def test_retrieve_metadata(store):
    """Test retrieve_metadata returns correct metadata."""
    test_dir = "tests/testdata/"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    pid = "jtao.1700.1"
    path = test_dir + pid
    filename = pid + ".xml"
    syspath = Path(test_dir) / filename
    _object_metadata = store.store_object(pid, path)
    _metadata_cid = store.store_metadata(pid, syspath, format_id)
    metadata_stream = store.retrieve_metadata(pid, format_id)
    metadata_content = metadata_stream.read().decode("utf-8")
    metadata_stream.close()
    metadata = syspath.read_bytes()
    assert metadata.decode("utf-8") == metadata_content


def test_retrieve_metadata_default_format_id(store):
    """Test retrieve_metadata retrieves expected metadata with default format_id."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    filename = pid + ".xml"
    syspath = Path(test_dir) / filename
    _object_metadata = store.store_object(pid, path)
    _metadata_cid = store.store_metadata(pid, syspath)
    metadata_stream = store.retrieve_metadata(pid)
    metadata_content = metadata_stream.read().decode("utf-8")
    metadata_stream.close()
    metadata = syspath.read_bytes()
    assert metadata.decode("utf-8") == metadata_content


def test_retrieve_metadata_bytes_pid_invalid(store):
    """Test retrieve_metadata raises error when supplied with bad pid."""
    format_id = "http://ns.dataone.org/service/types/v2.0"
    pid = "jtao.1700.1"
    pid_does_not_exist = pid + "test"
    with pytest.raises(ValueError):
        store.retrieve_metadata(pid_does_not_exist, format_id)


def test_retrieve_metadata_bytes_pid_empty(store):
    """Test retrieve_metadata raises error when supplied with empty pid."""
    format_id = "http://ns.dataone.org/service/types/v2.0"
    pid = "    "
    with pytest.raises(ValueError):
        store.retrieve_metadata(pid, format_id)


def test_retrieve_metadata_format_id_empty(store):
    """Test retrieve_metadata raises error when supplied with empty format_id."""
    format_id = ""
    pid = "jtao.1700.1"
    with pytest.raises(ValueError):
        store.retrieve_metadata(pid, format_id)


def test_retrieve_metadata_format_id_empty_spaces(store):
    """Test retrieve_metadata raises error when supplied with empty spaces format_id."""
    format_id = "    "
    pid = "jtao.1700.1"
    with pytest.raises(ValueError):
        store.retrieve_metadata(pid, format_id)


def test_delete_objects(pids, store):
    """Test delete_object successfully deletes objects from /objects."""
    test_dir = "tests/testdata/"
    entity = "objects"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        object_metadata = store.store_object(pid, path)
        store.tag_object(pid, object_metadata.id)
        _metadata_cid = store.store_metadata(pid, syspath, format_id)
        store.delete_object(pid)
    assert store.count(entity) == 0


def test_delete_objects_pid_refs_file(pids, store):
    """Test delete_object deletes the pid refs file containing the cid."""
    test_dir = "tests/testdata/"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        object_metadata = store.store_object(pid, path)
        store.tag_object(pid, object_metadata.id)
        _metadata_cid = store.store_metadata(pid, syspath, format_id)
        store.delete_object(pid)
        pid_refs_file_path = store.get_refs_abs_path("pid", pid)
        assert not os.path.exists(pid_refs_file_path)


def test_delete_objects_cid_refs_file(pids, store):
    """Test delete_object deletes the cid refs file containing the cid."""
    test_dir = "tests/testdata/"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        object_metadata = store.store_object(pid, path)
        cid = object_metadata.id
        store.tag_object(pid, cid)
        _metadata_cid = store.store_metadata(pid, syspath, format_id)
        store.delete_object(pid)
        cid_refs_file_path = store.get_refs_abs_path("cid", cid)
        assert not os.path.exists(cid_refs_file_path)


def test_delete_objects_cid_refs_file_with_pid_refs_remaining(pids, store):
    """Test delete_object does not delete the cid refs file that still contains ref."""
    test_dir = "tests/testdata/"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        object_metadata = store.store_object(pid, path)
        cid = object_metadata.id
        store.tag_object(pid, cid)
        cid_refs_abs_path = store.get_refs_abs_path("cid", cid)
        # pylint: disable=W0212
        store._update_cid_refs(cid_refs_abs_path, "dou.test.1")
        _metadata_cid = store.store_metadata(pid, syspath, format_id)
        store.delete_object(pid)
        cid_refs_file_path = store.get_refs_abs_path("cid", cid)
        assert os.path.exists(cid_refs_file_path)


def test_delete_object_pid_empty(store):
    """Test delete_object raises error when empty pid supplied."""
    pid = "    "
    with pytest.raises(ValueError):
        store.delete_object(pid)


def test_delete_object_pid_none(store):
    """Test delete_object raises error when pid is 'None'."""
    pid = None
    with pytest.raises(ValueError):
        store.delete_object(pid)


def test_delete_metadata(pids, store):
    """Test delete_metadata successfully deletes metadata."""
    test_dir = "tests/testdata/"
    entity = "metadata"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        _object_metadata = store.store_object(pid, path)
        _metadata_cid = store.store_metadata(pid, syspath, format_id)
        store.delete_metadata(pid, format_id)
    assert store.count(entity) == 0


def test_delete_metadata_default_format_id(store, pids):
    """Test delete_metadata deletes successfully with default format_id."""
    test_dir = "tests/testdata/"
    entity = "metadata"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        _object_metadata = store.store_object(pid, path)
        _metadata_cid = store.store_metadata(pid, syspath)
        store.delete_metadata(pid)
    assert store.count(entity) == 0


def test_delete_metadata_pid_empty(store):
    """Test delete_object raises error when empty pid supplied."""
    format_id = "http://ns.dataone.org/service/types/v2.0"
    pid = "    "
    with pytest.raises(ValueError):
        store.delete_metadata(pid, format_id)


def test_delete_metadata_pid_none(store):
    """Test delete_object raises error when pid is 'None'."""
    format_id = "http://ns.dataone.org/service/types/v2.0"
    pid = None
    with pytest.raises(ValueError):
        store.delete_metadata(pid, format_id)


def test_delete_metadata_format_id_empty(store):
    """Test delete_object raises error when empty format_id supplied."""
    format_id = "    "
    pid = "jtao.1700.1"
    with pytest.raises(ValueError):
        store.delete_metadata(pid, format_id)


def test_get_hex_digest(store):
    """Test get_hex_digest for expected value."""
    test_dir = "tests/testdata/"
    format_id = "http://ns.dataone.org/service/types/v2.0"
    pid = "jtao.1700.1"
    path = test_dir + pid
    filename = pid + ".xml"
    syspath = Path(test_dir) / filename
    object_metadata = store.store_object(pid, path)
    store.tag_object(pid, object_metadata.id)
    _metadata_cid = store.store_metadata(pid, syspath, format_id)
    sha3_256_hex_digest = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    sha3_256_get = store.get_hex_digest(pid, "sha3_256")
    assert sha3_256_hex_digest == sha3_256_get


def test_get_hex_digest_pid_not_found(store):
    """Test get_hex_digest raises error when supplied with bad pid."""
    pid = "jtao.1700.1"
    pid_does_not_exist = pid + "test"
    algorithm = "sha256"
    with pytest.raises(FileNotFoundError):
        store.get_hex_digest(pid_does_not_exist, algorithm)


def test_get_hex_digest_pid_unsupported_algorithm(store):
    """Test get_hex_digest raises error when supplied with unsupported algorithm."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    filename = pid + ".xml"
    syspath = Path(test_dir) / filename
    syspath.read_bytes()
    _object_metadata = store.store_object(pid, path)
    algorithm = "sm3"
    with pytest.raises(ValueError):
        store.get_hex_digest(pid, algorithm)


def test_get_hex_digest_pid_empty(store):
    """Test get_hex_digest raises error when supplied pid is empty."""
    pid = "    "
    algorithm = "sm3"
    with pytest.raises(ValueError):
        store.get_hex_digest(pid, algorithm)


def test_get_hex_digest_pid_none(store):
    """Test get_hex_digest raises error when supplied pid is 'None'."""
    pid = None
    algorithm = "sm3"
    with pytest.raises(ValueError):
        store.get_hex_digest(pid, algorithm)


def test_get_hex_digest_algorithm_empty(store):
    """Test get_hex_digest raises error when supplied algorithm is empty."""
    pid = "jtao.1700.1"
    algorithm = "     "
    with pytest.raises(ValueError):
        store.get_hex_digest(pid, algorithm)


def test_get_hex_digest_algorithm_none(store):
    """Test get_hex_digest raises error when supplied algorithm is 'None'."""
    pid = "jtao.1700.1"
    algorithm = None
    with pytest.raises(ValueError):
        store.get_hex_digest(pid, algorithm)
