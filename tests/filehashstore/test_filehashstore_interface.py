"""Test module for FileHashStore HashStore interface methods."""

import io
import os
from pathlib import Path
from threading import Thread
import random
import threading
import time
import pytest

from hashstore.filehashstore_exceptions import (
    NonMatchingChecksum,
    NonMatchingObjSize,
    PidRefsDoesNotExist,
    UnsupportedAlgorithm,
    HashStoreRefsAlreadyExists,
    PidRefsAlreadyExistsError,
)

# pylint: disable=W0212


# Define a mark to be used to label slow tests
slow_test = pytest.mark.skipif(
    "not config.getoption('--run-slow')",
    reason="Only run when --run-slow is given",
)


def test_store_object_refs_files_and_object(pids, store):
    """Test store object stores objects and creates reference files."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = Path(test_dir + pid.replace("/", "_"))
        object_metadata = store.store_object(pid, path)
        assert object_metadata.cid == pids[pid][store.algorithm]
    assert store._count("objects") == 3
    assert store._count("pid") == 3
    assert store._count("cid") == 3


def test_store_object_only_object(pids, store):
    """Test store object stores an object only (no reference files will be created)"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = Path(test_dir + pid.replace("/", "_"))
        object_metadata = store.store_object(data=path)
        assert object_metadata.cid == pids[pid][store.algorithm]
    assert store._count("objects") == 3
    assert store._count("pid") == 0
    assert store._count("cid") == 0


def test_store_object_files_path(pids, store):
    """Test store object when given a path object."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = Path(test_dir + pid.replace("/", "_"))
        _object_metadata = store.store_object(pid, path)
        assert store._exists("objects", pids[pid][store.algorithm])
    assert store._count("objects") == 3


def test_store_object_files_string(pids, store):
    """Test store object when given a string object."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path_string = test_dir + pid.replace("/", "_")
        _object_metadata = store.store_object(pid, path_string)
        assert store._exists("objects", pids[pid][store.algorithm])
    assert store._count("objects") == 3


def test_store_object_files_input_stream(pids, store):
    """Test store object when given a stream object."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        input_stream = io.open(path, "rb")
        _object_metadata = store.store_object(pid, input_stream)
        input_stream.close()
        assert store._exists("objects", pids[pid][store.algorithm])
    assert store._count("objects") == 3


def test_store_object_cid(pids, store):
    """Test store object returns expected content identifier."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)
        assert object_metadata.cid == pids[pid][store.algorithm]


def test_store_object_pid(pids, store):
    """Test store object returns expected persistent identifier."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)
        assert object_metadata.pid == pid


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


def test_store_object_data_incorrect_type_none(store):
    """Test store object raises error when data is 'None'."""
    pid = "jtao.1700.1"
    path = None
    with pytest.raises(TypeError):
        store.store_object(pid, data=path)


def test_store_object_data_incorrect_type_empty(store):
    """Test store object raises error when data is an empty string."""
    pid = "jtao.1700.1"
    path = ""
    with pytest.raises(TypeError):
        store.store_object(pid, data=path)


def test_store_object_data_incorrect_type_empty_spaces(store):
    """Test store object raises error when data is an empty string with spaces."""
    pid = "jtao.1700.1"
    path = "   "
    with pytest.raises(TypeError):
        store.store_object(pid, data=path)


def test_store_object_data_incorrect_type_special_characters(store):
    """Test store object raises error when data is empty string with special characters"""
    pid = "jtao.1700.1"
    path = "     \n\t"
    with pytest.raises(TypeError):
        store.store_object(pid, data=path)


def test_store_object_data_incorrect_type_path_with_special_character(store):
    """Test store object raises error when data path contains special characters."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid + "\n"
    with pytest.raises(ValueError):
        store.store_object("", path)


def test_store_object_additional_algorithm_invalid(store):
    """Test store object raises error when supplied with unsupported algorithm."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_not_in_list = "abc"
    with pytest.raises(UnsupportedAlgorithm):
        store.store_object(pid, path, algorithm_not_in_list)


def test_store_object_additional_algorithm_hyphen_uppercase(pids, store):
    """Test store object accepts an additional algo that's supported in uppercase."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_with_hyphen_and_upper = "SHA-384"
    object_metadata = store.store_object(pid, path, algorithm_with_hyphen_and_upper)
    sha256_cid = object_metadata.hex_digests.get("sha384")
    assert sha256_cid == pids[pid]["sha384"]
    assert store._exists("objects", pids[pid][store.algorithm])


def test_store_object_additional_algorithm_hyphen_lowercase(pids, store):
    """Test store object accepts an additional algo that's supported in lowercase."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_other = "sha3-256"
    object_metadata = store.store_object(pid, path, algorithm_other)
    additional_sha3_256_hex_digest = object_metadata.hex_digests.get("sha3_256")
    sha3_256_checksum = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    assert additional_sha3_256_hex_digest == sha3_256_checksum
    assert store._exists("objects", pids[pid][store.algorithm])


def test_store_object_additional_algorithm_underscore(pids, store):
    """Test store object accepts an additional algo that's supported with underscore."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_other = "sha3_256"
    object_metadata = store.store_object(pid, path, algorithm_other)
    additional_sha3_256_hex_digest = object_metadata.hex_digests.get("sha3_256")
    sha3_256_checksum = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    assert additional_sha3_256_hex_digest == sha3_256_checksum
    assert store._exists("objects", pids[pid][store.algorithm])


def test_store_object_checksum_correct(store):
    """Test store object does not throw exception with good checksum."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    checksum_algo = "sha3_256"
    checksum_correct = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    _object_metadata = store.store_object(
        pid, path, checksum=checksum_correct, checksum_algorithm=checksum_algo
    )
    assert store._count("objects") == 1


def test_store_object_checksum_correct_and_additional_algo(store):
    """Test store object with good checksum and an additional algorithm."""
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
    """Test store object does not throw exception with duplicate algorithms (de-dupes)."""
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


def test_store_object_checksum_empty(store):
    """Test store object raises error when checksum_algorithm supplied with
    an empty checksum."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    checksum_algorithm = "sha3_256"
    with pytest.raises(ValueError):
        store.store_object(
            pid, path, checksum="", checksum_algorithm=checksum_algorithm
        )


def test_store_object_checksum_empty_spaces(store):
    """Test store object raises error when checksum_algorithm supplied and
    checksum is empty with spaces."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    checksum_algorithm = "sha3_256"
    with pytest.raises(ValueError):
        store.store_object(
            pid, path, checksum="  ", checksum_algorithm=checksum_algorithm
        )


def test_store_object_checksum_incorrect_checksum(store):
    """Test store object raises error when supplied with incorrect checksum."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_other = "sha224"
    checksum_incorrect = (
        "bbbb069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    with pytest.raises(NonMatchingChecksum):
        store.store_object(
            pid, path, checksum=checksum_incorrect, checksum_algorithm=algorithm_other
        )


def test_store_object_checksum_unsupported_checksum_algo(store):
    """Test store object raises error when supplied with unsupported checksum algo."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    algorithm_other = "sha3_256"
    checksum_incorrect = (
        "bbbb069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    with pytest.raises(UnsupportedAlgorithm):
        store.store_object(
            pid, path, checksum=algorithm_other, checksum_algorithm=checksum_incorrect
        )


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


def test_store_object_checksum_algorithm_empty_spaces(store):
    """Test store object raises error when checksum is supplied and with empty
    spaces as the checksum_algorithm."""
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


def test_store_object_checksum_algorithm_special_character(store):
    """Test store object raises error when checksum is supplied and with special characters
    as the checksum_algorithm."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    checksum_correct = (
        "b748069cd0116ba59638e5f3500bbff79b41d6184bc242bd71f5cbbb8cf484cf"
    )
    with pytest.raises(ValueError):
        store.store_object(
            pid, path, checksum=checksum_correct, checksum_algorithm="\n"
        )


def test_store_object_duplicate_does_not_store_duplicate(store):
    """Test that storing duplicate object does not store object twice."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    # Store first blob
    _object_metadata_one = store.store_object(pid, path)
    # Store second blob
    pid_that_refs_existing_cid = "dou.test.1"
    _object_metadata_two = store.store_object(pid_that_refs_existing_cid, path)
    # Confirm only one object exists and the tmp file created is deleted
    assert store._count("objects") == 1


def test_store_object_duplicate_object_references_file_count(store):
    """Test that storing a duplicate object but with different pids creates the expected
    amount of reference files."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    # Store with first pid
    _object_metadata_one = store.store_object(pid, path)
    # Store with second pid
    pid_two = "dou.test.1"
    _object_metadata_two = store.store_object(pid_two, path)
    # Store with third pid
    pid_three = "dou.test.2"
    _object_metadata_three = store.store_object(pid_three, path)
    # Confirm that there are 3 pid reference files
    assert store._count("pid") == 3
    # Confirm that there are 1 cid reference files
    assert store._count("cid") == 1
    assert store._count("objects") == 1


def test_store_object_duplicate_object_references_file_content(pids, store):
    """Test that storing duplicate object but different pid updates the cid refs file
    with the correct amount of pids and content."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    # Store with first pid
    store.store_object(pid, path)
    # Store with second pid
    pid_two = "dou.test.1"
    store.store_object(pid_two, path)
    # Store with third pid
    pid_three = "dou.test.2"
    store.store_object(pid_three, path)
    # Confirm the content of the cid reference files
    cid_ref_abs_path = store._get_hashstore_cid_refs_path(pids[pid][store.algorithm])
    cid_count = 0
    with open(cid_ref_abs_path, "r", encoding="utf8") as f:
        for _, line in enumerate(f, start=1):
            cid_count += 1
            value = line.strip()
            assert value == pid or value == pid_two or value == pid_three

    assert cid_count == 3


def test_store_object_duplicate_raises_error_with_bad_validation_data(pids, store):
    """Test store duplicate object throws exception when the data to validate against
    is incorrect."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    # Store first blob
    _object_metadata_one = store.store_object(pid, path)
    # Store second blob
    with pytest.raises(NonMatchingChecksum):
        _object_metadata_two = store.store_object(
            pid, path, checksum="nonmatchingchecksum", checksum_algorithm="sha256"
        )
    assert store._count("objects") == 1
    # Confirm tmp files created during this process was handled
    assert store._count("tmp") == 0
    assert store._exists("objects", pids[pid][store.algorithm])


def test_store_object_with_obj_file_size(store, pids):
    """Test store object stores object with correct file sizes."""
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
        with pytest.raises(NonMatchingObjSize):
            store.store_object(pid, path, expected_object_size=obj_file_size)
    assert store._count("objects") == 0


def test_store_object_with_obj_file_size_non_integer(store, pids):
    """Test store object throws exception with a non integer value (ex. a string)
    as the file size."""
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

    def store_object_wrapper(obj_pid, obj_path):
        try:
            store.store_object(obj_pid, obj_path)  # Call store_object inside the thread
        # pylint: disable=W0718
        except Exception as e:
            assert (
                type(e).__name__ == "HashStoreRefsAlreadyExists"
                or type(e).__name__ == "StoreObjectForPidAlreadyInProgress"
            )

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
    assert store._count(entity) == 1
    assert store._exists(entity, pids[pid][store.algorithm])


# Note:
# Multiprocessing has been tested through the HashStore client using
# metacat db data from 'test.arcticdata.io'. When time-permitting,
# implement a multiprocessing test


def test_store_object_threads_multiple_pids_one_cid_content(pids, store):
    """Test store object thread lock and refs files content"""
    entity = "objects"
    test_dir = "tests/testdata/"
    path = test_dir + "jtao.1700.1"
    pid_list = ["jtao.1700.1"]
    for n in range(0, 5):
        pid_list.append(f"dou.test.{n}")

    def store_object_wrapper(obj_pid, obj_path):
        store.store_object(obj_pid, obj_path)  # Call store_object inside the thread

    thread1 = Thread(target=store_object_wrapper, args=(pid_list[0], path))
    thread2 = Thread(target=store_object_wrapper, args=(pid_list[1], path))
    thread3 = Thread(target=store_object_wrapper, args=(pid_list[2], path))
    thread4 = Thread(target=store_object_wrapper, args=(pid_list[3], path))
    thread5 = Thread(target=store_object_wrapper, args=(pid_list[4], path))
    thread6 = Thread(target=store_object_wrapper, args=(pid_list[5], path))
    thread1.start()
    thread2.start()
    thread3.start()
    thread4.start()
    thread5.start()
    thread6.start()
    thread1.join()
    thread2.join()
    thread3.join()
    thread4.join()
    thread5.join()
    thread6.join()
    # All threads will succeed, file count must still be 1
    assert store._count(entity) == 1
    assert store._exists(entity, pids["jtao.1700.1"][store.algorithm])

    cid_refs_path = store._get_hashstore_cid_refs_path(
        "94f9b6c88f1f458e410c30c351c6384ea42ac1b5ee1f8430d3e365e43b78a38a"
    )
    number_of_pids_reffed = 0
    with open(cid_refs_path, "r", encoding="utf8") as ref_file:
        # Confirm that pid is not currently already tagged
        for pid in ref_file:
            if pid.strip() in pid_list:
                number_of_pids_reffed += 1

    assert number_of_pids_reffed == 6


def test_store_object_threads_multiple_pids_one_cid_files(store):
    """Test store object with threads produces the expected amount of files"""
    test_dir = "tests/testdata/"
    path = test_dir + "jtao.1700.1"
    pid_list = ["jtao.1700.1"]
    for n in range(0, 5):
        pid_list.append(f"dou.test.{n}")

    def store_object_wrapper(obj_pid, obj_path):
        store.store_object(obj_pid, obj_path)  # Call store_object inside the thread

    thread1 = Thread(target=store_object_wrapper, args=(pid_list[0], path))
    thread2 = Thread(target=store_object_wrapper, args=(pid_list[1], path))
    thread3 = Thread(target=store_object_wrapper, args=(pid_list[2], path))
    thread4 = Thread(target=store_object_wrapper, args=(pid_list[3], path))
    thread5 = Thread(target=store_object_wrapper, args=(pid_list[4], path))
    thread6 = Thread(target=store_object_wrapper, args=(pid_list[5], path))
    thread1.start()
    thread2.start()
    thread3.start()
    thread4.start()
    thread5.start()
    thread6.start()
    thread1.join()
    thread2.join()
    thread3.join()
    thread4.join()
    thread5.join()
    thread6.join()

    # Confirm that tmp files do not remain in refs
    def folder_has_files(folder_path):
        # Iterate over directory contents
        for _, _, files in os.walk(folder_path):
            if files:  # If there are any files in the folder
                print(files)
                return True
        return False

    # Confirm that tmp files do not remain in refs
    def get_number_of_files(folder_path):
        # Iterate over directory contents
        file_count = 0
        for _, _, files in os.walk(folder_path):
            if files:  # If there are any files in the folder
                file_count += len(files)
        return file_count

    assert get_number_of_files(store.refs / "pids") == 6
    assert get_number_of_files(store.refs / "cids") == 1
    assert folder_has_files(store.refs / "tmp") is False


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

    def store_object_wrapper(obj_pid, path):
        print(store.root)
        while not interrupt_flag:
            store.store_object(obj_pid, path)  # Call store_object inside the thread

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
    object_metadata_id = object_metadata.cid
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
    object_metadata_id = object_metadata.cid
    assert object_metadata_id == object_metadata.hex_digests.get("sha256")


def test_tag_object(pids, store):
    """Test tag_object does not throw exception when successful."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(None, path)
        store.tag_object(pid, object_metadata.cid)
    assert store._count("pid") == 3
    assert store._count("cid") == 3


def test_tag_object_pid_refs_not_found_cid_refs_found(store):
    """Test tag_object updates a cid reference file that already exists."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid.replace("/", "_")
    # Store data only
    object_metadata = store.store_object(None, path)
    cid = object_metadata.cid
    # Tag object
    store.tag_object(pid, cid)
    # Tag the cid with another pid
    additional_pid = "dou.test.1"
    store.tag_object(additional_pid, cid)

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


def test_tag_object_hashstore_refs_already_exist(pids, store):
    """Confirm that tag throws HashStoreRefsAlreadyExists when refs already exist"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)

        with pytest.raises(HashStoreRefsAlreadyExists):
            store.tag_object(pid, object_metadata.cid)


def test_tag_object_pid_refs_already_exist(pids, store):
    """Confirm that tag throws PidRefsAlreadyExistsError when a pid refs already exists"""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)
        cid_refs_file_path = store._get_hashstore_cid_refs_path(object_metadata.cid)
        os.remove(cid_refs_file_path)

        with pytest.raises(PidRefsAlreadyExistsError):
            store.tag_object(pid, "adifferentcid")


def test_delete_if_invalid_object(pids, store):
    """Test delete_if_invalid_object does not throw exception given good arguments."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(data=path)
        checksum = object_metadata.hex_digests.get(store.algorithm)
        checksum_algorithm = store.algorithm
        expected_file_size = object_metadata.obj_size
        store.delete_if_invalid_object(
            object_metadata, checksum, checksum_algorithm, expected_file_size
        )
        assert store._exists("objects", object_metadata.cid)


def test_delete_if_invalid_object_supported_other_algo_not_in_default(pids, store):
    """Test delete_if_invalid_object does not throw exception when supported add algo is
    supplied."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        supported_algo = "sha224"
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(data=path)
        checksum = pids[pid][supported_algo]
        expected_file_size = object_metadata.obj_size
        store.delete_if_invalid_object(
            object_metadata, checksum, supported_algo, expected_file_size
        )
        assert store._exists("objects", object_metadata.cid)


def test_delete_if_invalid_object_exception_incorrect_object_metadata_type(pids, store):
    """Test delete_if_invalid_object throws exception when incorrect obj type is given to
    object_metadata arg."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(data=path)
        checksum = object_metadata.hex_digests.get(store.algorithm)
        checksum_algorithm = store.algorithm
        expected_file_size = object_metadata.obj_size
        with pytest.raises(ValueError):
            store.delete_if_invalid_object(
                "not_object_metadata", checksum, checksum_algorithm, expected_file_size
            )


def test_delete_if_invalid_object_exception_incorrect_size(pids, store):
    """Test delete_if_invalid_object throws exception when incorrect size is supplied and that data
    object is deleted as we are storing without a pid."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(data=path)
        checksum = object_metadata.hex_digests.get(store.algorithm)
        checksum_algorithm = store.algorithm

        with pytest.raises(NonMatchingObjSize):
            store.delete_if_invalid_object(
                object_metadata, checksum, checksum_algorithm, 1000
            )

        assert not store._exists("objects", object_metadata.cid)


def test_delete_if_invalid_object_exception_incorrect_size_object_exists(pids, store):
    """Test delete_if_invalid_object throws exception when incorrect size is supplied and that data
    object is not deleted since it already exists (a cid refs file is present)."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        store.store_object(pid, data=path)
    # Store again without pid and wrong object size
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(data=path)
        checksum = object_metadata.hex_digests.get(store.algorithm)
        checksum_algorithm = store.algorithm

        with pytest.raises(NonMatchingObjSize):
            store.delete_if_invalid_object(
                object_metadata, checksum, checksum_algorithm, 1000
            )

        assert store._exists("objects", object_metadata.cid)
        assert store._count("tmp") == 0


def test_delete_if_invalid_object_exception_incorrect_checksum(pids, store):
    """Test delete_if_invalid_object throws exception when incorrect checksum is supplied."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(data=path)
        checksum_algorithm = store.algorithm
        expected_file_size = object_metadata.obj_size

        with pytest.raises(NonMatchingChecksum):
            store.delete_if_invalid_object(
                object_metadata, "abc123", checksum_algorithm, expected_file_size
            )

        assert not store._exists("objects", object_metadata.cid)


def test_delete_if_invalid_object_exception_incorrect_checksum_algo(pids, store):
    """Test delete_if_invalid_object throws exception when unsupported algorithm is supplied."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(data=path)
        checksum = object_metadata.hex_digests.get(store.algorithm)
        expected_file_size = object_metadata.obj_size
        with pytest.raises(UnsupportedAlgorithm):
            store.delete_if_invalid_object(
                object_metadata, checksum, "md2", expected_file_size
            )

        assert store._exists("objects", object_metadata.cid)
        assert store._count("tmp") == 0


def test_delete_if_invalid_object_exception_supported_other_algo_bad_checksum(
    pids, store
):
    """Test delete_if_invalid_object throws exception when incorrect checksum is supplied."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(data=path)
        checksum = object_metadata.hex_digests.get(store.algorithm)
        expected_file_size = object_metadata.obj_size
        with pytest.raises(NonMatchingChecksum):
            store.delete_if_invalid_object(
                object_metadata, checksum, "sha224", expected_file_size
            )

        assert not store._exists("objects", object_metadata.cid)


def test_store_metadata(pids, store):
    """Test store_metadata."""
    test_dir = "tests/testdata/"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        stored_metadata_path = store.store_metadata(pid, syspath, format_id)
        # Manually calculate expected path
        metadata_directory = store._computehash(pid)
        metadata_document_name = store._computehash(pid + format_id)
        rel_path = Path(*store._shard(metadata_directory))
        full_path = (
            store._get_store_path("metadata") / rel_path / metadata_document_name
        )
        assert stored_metadata_path == str(full_path)
    assert store._count("metadata") == 3


def test_store_metadata_one_pid_multiple_docs_correct_location(store):
    """Test store_metadata for a pid with multiple metadata documents."""
    test_dir = "tests/testdata/"
    entity = "metadata"
    pid = "jtao.1700.1"
    filename = pid.replace("/", "_") + ".xml"
    syspath = Path(test_dir) / filename
    metadata_directory = store._computehash(pid)
    rel_path = Path(*store._shard(metadata_directory))
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    format_id3 = "http://ns.dataone.org/service/types/v3.0"
    format_id4 = "http://ns.dataone.org/service/types/v4.0"
    stored_metadata_path = store.store_metadata(pid, syspath, format_id)
    stored_metadata_path3 = store.store_metadata(pid, syspath, format_id3)
    stored_metadata_path4 = store.store_metadata(pid, syspath, format_id4)

    metadata_document_name = store._computehash(pid + format_id)
    metadata_document_name3 = store._computehash(pid + format_id3)
    metadata_document_name4 = store._computehash(pid + format_id4)
    full_path = store._get_store_path("metadata") / rel_path / metadata_document_name
    full_path3 = store._get_store_path("metadata") / rel_path / metadata_document_name3
    full_path4 = store._get_store_path("metadata") / rel_path / metadata_document_name4

    assert stored_metadata_path == str(full_path)
    assert stored_metadata_path3 == str(full_path3)
    assert stored_metadata_path4 == str(full_path4)
    assert store._count(entity) == 3


def test_store_metadata_default_format_id(pids, store):
    """Test store_metadata returns expected id when storing with default format_id."""
    test_dir = "tests/testdata/"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        stored_metadata_path = store.store_metadata(pid, syspath)
        # Manually calculate expected path
        metadata_directory = store._computehash(pid)
        metadata_document_name = store._computehash(pid + format_id)
        rel_path = Path(*store._shard(metadata_directory))
        full_path = (
            store._get_store_path("metadata") / rel_path / metadata_document_name
        )
        assert stored_metadata_path == str(full_path)


def test_store_metadata_files_string(pids, store):
    """Test store_metadata with a string object to the metadata."""
    test_dir = "tests/testdata/"
    entity = "metadata"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath_string = str(Path(test_dir) / filename)
        stored_metadata_path = store.store_metadata(pid, syspath_string, format_id)
        assert store._exists(entity, stored_metadata_path)
    assert store._count(entity) == 3


def test_store_metadata_files_input_stream(pids, store):
    """Test store_metadata with a stream to  the metadata."""
    test_dir = "tests/testdata/"
    entity = "metadata"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath_string = str(Path(test_dir) / filename)
        syspath_stream = io.open(syspath_string, "rb")
        _stored_metadata_path = store.store_metadata(pid, syspath_stream, format_id)
        syspath_stream.close()
    assert store._count(entity) == 3


def test_store_metadata_pid_empty(store):
    """Test store_metadata raises error with an empty string as the pid."""
    test_dir = "tests/testdata/"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    pid = ""
    filename = pid.replace("/", "_") + ".xml"
    syspath_string = str(Path(test_dir) / filename)
    with pytest.raises(ValueError):
        store.store_metadata(pid, syspath_string, format_id)


def test_store_metadata_pid_empty_spaces(store):
    """Test store_metadata raises error with empty spaces as the pid."""
    test_dir = "tests/testdata/"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    pid = "   "
    filename = pid.replace("/", "_") + ".xml"
    syspath_string = str(Path(test_dir) / filename)
    with pytest.raises(ValueError):
        store.store_metadata(pid, syspath_string, format_id)


def test_store_metadata_pid_format_id_spaces(store):
    """Test store_metadata raises error with empty spaces as the format_id."""
    test_dir = "tests/testdata/"
    format_id = "       "
    pid = "jtao.1700.1"
    filename = pid.replace("/", "_") + ".xml"
    syspath_string = str(Path(test_dir) / filename)
    with pytest.raises(ValueError):
        store.store_metadata(pid, syspath_string, format_id)


def test_store_metadata_metadata_empty(store):
    """Test store_metadata raises error with empty spaces as the metadata path."""
    pid = "jtao.1700.1"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    syspath_string = "   "
    with pytest.raises(TypeError):
        store.store_metadata(pid, syspath_string, format_id)


def test_store_metadata_metadata_none(store):
    """Test store_metadata raises error with empty None metadata path."""
    pid = "jtao.1700.1"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    syspath_string = None
    with pytest.raises(TypeError):
        store.store_metadata(pid, syspath_string, format_id)


def test_store_metadata_metadata_path(pids, store):
    """Test store_metadata returns expected path to metadata document."""
    test_dir = "tests/testdata/"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        _object_metadata = store.store_object(pid, path)
        stored_metadata_path = store.store_metadata(pid, syspath, format_id)
        metadata_path = store._get_hashstore_metadata_path(stored_metadata_path)
        assert Path(stored_metadata_path) == metadata_path


def test_store_metadata_thread_lock(store):
    """Test store_metadata thread lock."""
    test_dir = "tests/testdata/"
    entity = "metadata"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
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
    assert store._count(entity) == 1


def test_retrieve_object(pids, store):
    """Test retrieve_object returns a stream to the correct object data."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)
        obj_stream = store.retrieve_object(pid)
        sha256_hex = store._computehash(obj_stream)
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
    with pytest.raises(PidRefsDoesNotExist):
        store.retrieve_object(pid_does_not_exist)


def test_retrieve_metadata(store):
    """Test retrieve_metadata returns a stream to the correct metadata."""
    test_dir = "tests/testdata/"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    pid = "jtao.1700.1"
    filename = pid + ".xml"
    syspath = Path(test_dir) / filename
    _stored_metadata_path = store.store_metadata(pid, syspath, format_id)
    metadata_stream = store.retrieve_metadata(pid, format_id)
    metadata_content = metadata_stream.read().decode("utf-8")
    metadata_stream.close()
    metadata = syspath.read_bytes()
    assert metadata.decode("utf-8") == metadata_content


def test_retrieve_metadata_default_format_id(store):
    """Test retrieve_metadata retrieves expected metadata without a format_id."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    filename = pid + ".xml"
    syspath = Path(test_dir) / filename
    _stored_metadata_path = store.store_metadata(pid, syspath)
    metadata_stream = store.retrieve_metadata(pid)
    metadata_content = metadata_stream.read().decode("utf-8")
    metadata_stream.close()
    metadata = syspath.read_bytes()
    assert metadata.decode("utf-8") == metadata_content


def test_retrieve_metadata_bytes_pid_invalid(store):
    """Test retrieve_metadata raises exception when supplied with pid with no system metadata."""
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    pid_does_not_exist = "jtao.1700.1.metadata.does.not.exist"
    with pytest.raises(ValueError):
        store.retrieve_metadata(pid_does_not_exist, format_id)


def test_retrieve_metadata_bytes_pid_empty(store):
    """Test retrieve_metadata raises exception when supplied with empty pid."""
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    pid = "    "
    with pytest.raises(ValueError):
        store.retrieve_metadata(pid, format_id)


def test_retrieve_metadata_format_id_empty(store):
    """Test retrieve_metadata raises error when supplied with an empty format_id."""
    format_id = ""
    pid = "jtao.1700.1"
    with pytest.raises(ValueError):
        store.retrieve_metadata(pid, format_id)


def test_retrieve_metadata_format_id_empty_spaces(store):
    """Test retrieve_metadata raises exception when supplied with empty spaces as the format_id."""
    format_id = "    "
    pid = "jtao.1700.1"
    with pytest.raises(ValueError):
        store.retrieve_metadata(pid, format_id)


def test_delete_object_object_deleted(pids, store):
    """Test delete_object successfully deletes object."""
    test_dir = "tests/testdata/"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        _object_metadata = store.store_object(pid, path)
        _stored_metadata_path = store.store_metadata(pid, syspath, format_id)
        store.delete_object(pid)
    assert store._count("objects") == 0


def test_delete_object_metadata_deleted(pids, store):
    """Test delete_object successfully deletes associated metadata files."""
    test_dir = "tests/testdata/"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        _object_metadata = store.store_object(pid, path)
        _stored_metadata_path = store.store_metadata(pid, syspath, format_id)
        store.delete_object(pid)
    assert store._count("metadata") == 0


def test_delete_object_refs_files_deleted(pids, store):
    """Test delete_object successfully deletes refs files."""
    test_dir = "tests/testdata/"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        _object_metadata = store.store_object(pid, path)
        _stored_metadata_path = store.store_metadata(pid, syspath, format_id)
        store.delete_object(pid)
    assert store._count("pid") == 0
    assert store._count("cid") == 0


def test_delete_object_pid_refs_file_deleted(pids, store):
    """Test delete_object deletes the associated pid refs file for the object."""
    test_dir = "tests/testdata/"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        _object_metadata = store.store_object(pid, path)
        _stored_metadata_path = store.store_metadata(pid, syspath, format_id)
        store.delete_object(pid)
        pid_refs_file_path = store._get_hashstore_pid_refs_path(pid)
        assert not os.path.exists(pid_refs_file_path)


def test_delete_object_cid_refs_file_deleted(pids, store):
    """Test delete_object deletes the associated cid refs file for the object."""
    test_dir = "tests/testdata/"
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        object_metadata = store.store_object(pid, path)
        _stored_metadata_path = store.store_metadata(pid, syspath, format_id)
        cid = object_metadata.cid
        store.delete_object(pid)
        cid_refs_file_path = store._get_hashstore_cid_refs_path(cid)
        assert not os.path.exists(cid_refs_file_path)


def test_delete_object_cid_refs_file_with_pid_refs_remaining(pids, store):
    """Test delete_object does not delete the cid refs file that still contains refs."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)
        cid = object_metadata.cid
        cid_refs_abs_path = store._get_hashstore_cid_refs_path(cid)
        store._update_refs_file(cid_refs_abs_path, "dou.test.1", "add")
        store.delete_object(pid)
        cid_refs_file_path = store._get_hashstore_cid_refs_path(cid)
        assert os.path.exists(cid_refs_file_path)
    assert store._count("cid") == 3


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
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        _stored_metadata_path = store.store_metadata(pid, syspath, format_id)
        store.delete_metadata(pid, format_id)
    assert store._count("metadata") == 0


def test_delete_metadata_one_pid_multiple_metadata_documents(store):
    """Test delete_metadata for a pid with multiple metadata documents deletes
    all associated metadata files as expected."""
    test_dir = "tests/testdata/"
    entity = "metadata"
    pid = "jtao.1700.1"
    filename = pid.replace("/", "_") + ".xml"
    syspath = Path(test_dir) / filename
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    format_id3 = "http://ns.dataone.org/service/types/v3.0"
    format_id4 = "http://ns.dataone.org/service/types/v4.0"
    _stored_metadata_path = store.store_metadata(pid, syspath, format_id)
    _stored_metadata_path3 = store.store_metadata(pid, syspath, format_id3)
    _stored_metadata_path4 = store.store_metadata(pid, syspath, format_id4)
    store.delete_metadata(pid)
    assert store._count(entity) == 0


def test_delete_metadata_specific_pid_multiple_metadata_documents(store):
    """Test delete_metadata for a pid with multiple metadata documents deletes
    only the specified metadata file."""
    test_dir = "tests/testdata/"
    entity = "metadata"
    pid = "jtao.1700.1"
    filename = pid.replace("/", "_") + ".xml"
    syspath = Path(test_dir) / filename
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    format_id3 = "http://ns.dataone.org/service/types/v3.0"
    format_id4 = "http://ns.dataone.org/service/types/v4.0"
    stored_metadata_path = store.store_metadata(pid, syspath, format_id)
    stored_metadata_path3 = store.store_metadata(pid, syspath, format_id3)
    _stored_metadata_path4 = store.store_metadata(pid, syspath, format_id4)
    store.delete_metadata(pid, format_id4)
    assert store._count(entity) == 2
    assert os.path.exists(stored_metadata_path)
    assert os.path.exists(stored_metadata_path3)


def test_delete_metadata_does_not_exist(pids, store):
    """Test delete_metadata does not throw exception when called to delete
    metadata that does not exist."""
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        store.delete_metadata(pid, format_id)


def test_delete_metadata_default_format_id(store, pids):
    """Test delete_metadata deletes successfully with default format_id."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        _stored_metadata_path = store.store_metadata(pid, syspath)
        store.delete_metadata(pid)
    assert store._count("metadata") == 0


def test_delete_metadata_pid_empty(store):
    """Test delete_metadata raises error when empty pid supplied."""
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    pid = "    "
    with pytest.raises(ValueError):
        store.delete_metadata(pid, format_id)


def test_delete_metadata_pid_none(store):
    """Test delete_metadata raises error when pid is 'None'."""
    format_id = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    pid = None
    with pytest.raises(ValueError):
        store.delete_metadata(pid, format_id)


def test_delete_metadata_format_id_empty(store):
    """Test delete_metadata raises error when empty format_id supplied."""
    format_id = "    "
    pid = "jtao.1700.1"
    with pytest.raises(ValueError):
        store.delete_metadata(pid, format_id)


def test_get_hex_digest(store):
    """Test get_hex_digest for expected value."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid
    _object_metadata = store.store_object(pid, path)
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
    with pytest.raises(PidRefsDoesNotExist):
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
    with pytest.raises(UnsupportedAlgorithm):
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


def test_store_and_delete_objects_100_pids_1_cid(store):
    """Test that deleting an object that is tagged with 100 pids successfully
    deletes all related files"""
    test_dir = "tests/testdata/"
    path = test_dir + "jtao.1700.1"
    refs_pids_path = store.root / "refs" / "pids"
    refs_cids_path = store.root / "refs" / "cids"
    # Store
    upper_limit = 101
    for i in range(1, upper_limit):
        pid_modified = f"dou.test.{str(i)}"
        store.store_object(pid_modified, path)
    assert sum([len(files) for _, _, files in os.walk(refs_pids_path)]) == 100
    assert sum([len(files) for _, _, files in os.walk(refs_cids_path)]) == 1
    assert store._count("objects") == 1
    # Delete
    for i in range(1, upper_limit):
        pid_modified = f"dou.test.{str(i)}"
        store.delete_object(pid_modified)
    assert sum([len(files) for _, _, files in os.walk(refs_pids_path)]) == 0
    assert sum([len(files) for _, _, files in os.walk(refs_cids_path)]) == 0
    assert store._count("objects") == 0


def test_store_and_delete_object_300_pids_1_cid_threads(store):
    """Test store object thread lock."""

    def store_object_wrapper(pid_var):
        try:
            test_dir = "tests/testdata/"
            path = test_dir + "jtao.1700.1"
            upper_limit = 101
            for i in range(1, upper_limit):
                pid_modified = f"dou.test.{pid_var}.{str(i)}"
                store.store_object(pid_modified, path)
        # pylint: disable=W0718
        except Exception as e:
            print(e)

    # Store
    thread1 = Thread(target=store_object_wrapper, args=("matt",))
    thread2 = Thread(target=store_object_wrapper, args=("matthew",))
    thread3 = Thread(target=store_object_wrapper, args=("matthias",))
    thread1.start()
    thread2.start()
    thread3.start()
    thread1.join()
    thread2.join()
    thread3.join()

    def delete_object_wrapper(pid_var):
        try:
            upper_limit = 101
            for i in range(1, upper_limit):
                pid_modified = f"dou.test.{pid_var}.{str(i)}"
                store.delete_object(pid_modified)
        # pylint: disable=W0718
        except Exception as e:
            print(e)

    # Delete
    thread4 = Thread(target=delete_object_wrapper, args=("matt",))
    thread5 = Thread(target=delete_object_wrapper, args=("matthew",))
    thread6 = Thread(target=delete_object_wrapper, args=("matthias",))
    thread4.start()
    thread5.start()
    thread6.start()
    thread4.join()
    thread5.join()
    thread6.join()

    refs_pids_path = store.root / "refs" / "pids"
    refs_cids_path = store.root / "refs" / "cids"
    assert sum([len(files) for _, _, files in os.walk(refs_pids_path)]) == 0
    assert sum([len(files) for _, _, files in os.walk(refs_cids_path)]) == 0
    assert store._count("objects") == 0
