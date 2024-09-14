"""Test module for FileHashStore's reference system to tag stored objects."""

import os
import shutil
import pytest

from hashstore.filehashstore_exceptions import (
    CidRefsContentError,
    CidRefsFileNotFound,
    HashStoreRefsAlreadyExists,
    PidRefsAlreadyExistsError,
    PidRefsContentError,
    PidRefsFileNotFound,
)

# pylint: disable=W0212

# TODO: Review 'tag_object' tests and split them into relevant 'store_hashstore_refs_files' tests


def test_tag_object(pids, store):
    """Test tag_object does not throw exception when successful."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(None, path)
        store.tag_object(pid, object_metadata.cid)
    assert store._count("pid") == 3
    assert store._count("cid") == 3


def test_tag_object_pid_refs_file_exists(pids, store):
    """Test tag_object creates the expected pid reference file."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(None, path)
        store.tag_object(pid, object_metadata.cid)
        pid_refs_file_path = store._get_hashstore_pid_refs_path(pid)
        assert os.path.exists(pid_refs_file_path)


def test_tag_object_cid_refs_file_exists(pids, store):
    """Test tag_object creates the cid reference file."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(None, path)
        cid = object_metadata.cid
        store.tag_object(pid, object_metadata.cid)
        cid_refs_file_path = store._get_hashstore_cid_refs_path(cid)
        assert os.path.exists(cid_refs_file_path)


def test_tag_object_pid_refs_file_content(pids, store):
    """Test tag_object created the pid reference file with the expected cid."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(None, path)
        store.tag_object(pid, object_metadata.cid)
        pid_refs_file_path = store._get_hashstore_pid_refs_path(pid)
        with open(pid_refs_file_path, "r", encoding="utf8") as f:
            pid_refs_cid = f.read()
        assert pid_refs_cid == object_metadata.cid


def test_tag_object_cid_refs_file_content(pids, store):
    """Test tag_object creates the cid reference file successfully with pid tagged."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(None, path)
        store.tag_object(pid, object_metadata.cid)
        cid_refs_file_path = store._get_hashstore_cid_refs_path(object_metadata.cid)
        with open(cid_refs_file_path, "r", encoding="utf8") as f:
            pid_refs_cid = f.read().strip()
        assert pid_refs_cid == pid


def test_tag_object_pid_refs_found_cid_refs_found(pids, store):
    """Test tag_object does not throw an exception when any refs file already exists
    and verifies the content, and does not double tag the cid refs file."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(None, path)
        cid = object_metadata.cid
        store.tag_object(pid, cid)

        with pytest.raises(HashStoreRefsAlreadyExists):
            store.tag_object(pid, cid)

        cid_refs_file_path = store._get_hashstore_cid_refs_path(object_metadata.cid)
        line_count = 0
        with open(cid_refs_file_path, "r", encoding="utf8") as ref_file:
            for _line in ref_file:
                line_count += 1
        assert line_count == 1


def test_tag_object_pid_refs_found_cid_refs_not_found(store):
    """Test that tag_object throws an exception when pid refs file exists, contains a
    different cid, and is correctly referenced in the associated cid refs file"""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid.replace("/", "_")
    _object_metadata = store.store_object(pid, path)

    with pytest.raises(PidRefsAlreadyExistsError):
        store.tag_object(pid, "another_cid_value_that_is_not_found")


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


def test_write_refs_file_ref_type_cid(store):
    """Test that write_refs_file writes a reference file."""
    tmp_root_path = store._get_store_path("refs") / "tmp"
    tmp_cid_refs_file = store._write_refs_file(tmp_root_path, "test_pid", "cid")
    assert os.path.exists(tmp_cid_refs_file)


def test_write_refs_file_ref_type_cid_content(pids, store):
    """Test that write_refs_file writes the expected content."""
    for pid in pids.keys():
        tmp_root_path = store._get_store_path("refs") / "tmp"
        tmp_cid_refs_file = store._write_refs_file(tmp_root_path, pid, "cid")
        with open(tmp_cid_refs_file, "r", encoding="utf8") as f:
            cid_ref_file_pid = f.read()

        assert pid == cid_ref_file_pid.strip()


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


def test_update_refs_file_content_pid_exists(pids, store):
    """Test that _update_refs_file does add a pid to a refs file that already
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


def test_write_refs_file_ref_type_pid(pids, store):
    """Test that write_pid_refs_file writes a reference file."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        tmp_root_path = store._get_store_path("refs") / "tmp"
        tmp_pid_refs_file = store._write_refs_file(tmp_root_path, cid, "pid")
        assert os.path.exists(tmp_pid_refs_file)


def test_write_refs_file_ref_type_content_pid(pids, store):
    """Test that write_pid_refs_file writes the expected content."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        tmp_root_path = store._get_store_path("refs") / "tmp"
        tmp_pid_refs_file = store._write_refs_file(tmp_root_path, cid, "pid")
        with open(tmp_pid_refs_file, "r", encoding="utf8") as f:
            pid_refs_cid = f.read()

        assert cid == pid_refs_cid


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

        cid_reference_list = [pid]
        for i in range(0, 5):
            store._update_refs_file(cid_ref_abs_path, f"dou.test.{i}", "add")
            cid_reference_list.append(f"dou.test.{i}")

        with pytest.raises(CidRefsContentError):
            store._verify_hashstore_references(pid, cid)
