"""Test module for FileHashStore's reference system to tag stored objects."""
import os
import pytest

# pylint: disable=W0212


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


def test_tag_object_cid_refs_update(pids, store):
    """Test tag object updates a cid reference file that already exists."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)
        cid = object_metadata.id
        store.tag_object(pid, cid)
        store.tag_object("dou.test.1", cid)
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        with open(cid_ref_abs_path, "r", encoding="utf8") as f:
            cid_ref_file_pid = f.read()

        assert "dou.test.1" in cid_ref_file_pid


def test_write_cid_refs_file(pids, store):
    """Test that write_cid_reference writes a reference file."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        store._write_cid_refs_file(cid_ref_abs_path, pid)
        assert os.path.exists(cid_ref_abs_path)


def test_write_cid_refs_file_content(pids, store):
    """Test that write_cid_ref_file writes the expected content."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        store._write_cid_refs_file(cid_ref_abs_path, pid)

        with open(cid_ref_abs_path, "r", encoding="utf8") as f:
            cid_ref_file_pid = f.read()

        assert pid == cid_ref_file_pid.strip()


def test_write_cid_refs_file_into_empty_file(pids, store):
    """Test that write_cid_reference writes an empty file."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        with open(cid_ref_abs_path, "w", encoding="utf8"):
            pass
        store._write_cid_refs_file(cid_ref_abs_path, pid)
        assert os.path.exists(cid_ref_abs_path)


def test_write_cid_refs_file_file_not_empty(pids, store):
    """Test that write_cid_reference does not overwrite an existing file."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        store._write_cid_refs_file(cid_ref_abs_path, pid)
        with pytest.raises(OSError):
            store._write_cid_refs_file(cid_ref_abs_path, "other_pid")


def test_update_cid_refs_content(pids, store):
    """Test that update_cid_ref updates the ref file as expected."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        store._write_cid_refs_file(cid_ref_abs_path, pid)

        pid_other = "dou.test.1"
        store._update_cid_refs(cid_ref_abs_path, pid_other)

        with open(cid_ref_abs_path, "r", encoding="utf8") as f:
            for _, line in enumerate(f, start=1):
                value = line.strip()
                assert value == pid or value == pid_other


def test_update_cid_refs_content_multiple(pids, store):
    """Test that update_cid_refs adds multiple references successfully."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        store._write_cid_refs_file(cid_ref_abs_path, pid)

        cid_reference_list = [pid]
        for i in range(0, 5):
            store._update_cid_refs(cid_ref_abs_path, f"dou.test.{i}")
            cid_reference_list.append(f"dou.test.{i}")

        line_count = 0
        with open(cid_ref_abs_path, "r", encoding="utf8") as f:
            for _, line in enumerate(f, start=1):
                line_count += 1
                value = line.strip()
                assert value in cid_reference_list

        assert line_count == 6


def test_update_cid_refs_content_pid_exists(pids, store):
    """Test that update_cid_ref throws exception if pid already exists."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        store._write_cid_refs_file(cid_ref_abs_path, pid)
        with pytest.raises(ValueError):
            store._update_cid_refs(cid_ref_abs_path, pid)


def test_update_cid_refs_content_cid_refs_does_not_exist(pids, store):
    """Test that update_cid_ref throws exception if cid refs file doesn't exist."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        with pytest.raises(FileNotFoundError):
            store._update_cid_refs(cid_ref_abs_path, pid)


def test_delete_cid_refs_pid(pids, store):
    """Test that delete_cid_refs_pid deletes the given pid from the ref file."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        store._write_cid_refs_file(cid_ref_abs_path, pid)

        pid_other = "dou.test.1"
        store._update_cid_refs(cid_ref_abs_path, pid_other)
        store._delete_cid_refs_pid(cid_ref_abs_path, pid)

        with open(cid_ref_abs_path, "r", encoding="utf8") as f:
            for _, line in enumerate(f, start=1):
                value = line.strip()
                print(value)
                assert value == pid_other


def test_delete_cid_refs_pid_pid_not_found(pids, store):
    """Test that delete_cid_refs_pid raises exception when pid not found."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        store._write_cid_refs_file(cid_ref_abs_path, pid)

        pid_other = "dou.test.1"
        store._update_cid_refs(cid_ref_abs_path, pid_other)
        with pytest.raises(ValueError):
            store._delete_cid_refs_pid(cid_ref_abs_path, "dou.not.found.1")


def test_delete_cid_refs_pid_file(pids, store):
    """Test that delete_cid_refs_file deletes a reference file."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        store._write_cid_refs_file(cid_ref_abs_path, pid)
        store._delete_cid_refs_pid(cid_ref_abs_path, pid)
        cid_refs_deleted = store._delete_cid_refs_file(cid_ref_abs_path)

        assert cid_refs_deleted
        assert not os.path.exists(cid_ref_abs_path)


def test_delete_cid_refs_file_file_not_empty(pids, store):
    """Test that delete_cid_refs_file raises an exception when refs file is not empty."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        store._write_cid_refs_file(cid_ref_abs_path, pid)
        with pytest.raises(OSError):
            store._delete_cid_refs_file(cid_ref_abs_path)


def test_delete_cid_refs_file_file_not_found(pids, store):
    """Test that delete_cid_refs_file raises an exception when refs file not found."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        with pytest.raises(FileNotFoundError):
            store._delete_cid_refs_file(cid_ref_abs_path)


def test_write_pid_refs_file(pids, store):
    """Test that write_pid_refs_file writes a reference file."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        pid_ref_abs_path = store.get_refs_abs_path("pid", pid)
        store.create_path(os.path.dirname(pid_ref_abs_path))
        store._write_pid_refs_file(pid_ref_abs_path, cid)
        assert os.path.exists(pid_ref_abs_path)


def test_write_pid_refs_file_content(pids, store):
    """Test that write_pid_refs_file writes the expected content."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        pid_ref_abs_path = store.get_refs_abs_path("pid", pid)
        store.create_path(os.path.dirname(pid_ref_abs_path))
        store._write_pid_refs_file(pid_ref_abs_path, cid)

        with open(pid_ref_abs_path, "r", encoding="utf8") as f:
            pid_refs_cid = f.read()

        assert cid == pid_refs_cid


def test_delete_pid_refs_file(pids, store):
    """Test that delete_pid_refs_file deletes a reference file."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        pid_ref_abs_path = store.get_refs_abs_path("pid", pid)
        store.create_path(os.path.dirname(pid_ref_abs_path))
        store._write_pid_refs_file(pid_ref_abs_path, cid)
        store._delete_pid_refs_file(pid_ref_abs_path)

        assert not os.path.exists(pid_ref_abs_path)


def test_delete_pid_refs_file_file_not_found(pids, store):
    """Test that delete_pid_refs_file raises an exception when refs file not found."""
    for pid in pids.keys():
        pid_ref_abs_path = store.get_refs_abs_path("pid", pid)
        with pytest.raises(FileNotFoundError):
            store._delete_cid_refs_file(pid_ref_abs_path)


def test_validate_references_pid_refs_file_missing(pids, store):
    """Test that validate_references throws exception when pid refs file is missing."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        with pytest.raises(FileNotFoundError):
            store._validate_references(pid, cid)


def test_validate_references_pid_refs_incorrect_cid(pids, store):
    """Test that validate_references throws exception when pid refs file cid is incorrect."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        pid_ref_abs_path = store.get_refs_abs_path("pid", pid)
        store.create_path(os.path.dirname(pid_ref_abs_path))
        store._write_pid_refs_file(pid_ref_abs_path, "bad_cid")
        with pytest.raises(FileNotFoundError):
            store._validate_references(pid, cid)


def test_validate_references_cid_refs_file_missing(pids, store):
    """Test that validate_references throws exception when cid refs file is missing."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        pid_ref_abs_path = store.get_refs_abs_path("pid", pid)
        store.create_path(os.path.dirname(pid_ref_abs_path))
        store._write_pid_refs_file(pid_ref_abs_path, cid)
        with pytest.raises(FileNotFoundError):
            store._validate_references(pid, cid)


def test_validate_references_cid_refs_file_missing_pid(pids, store):
    """Test that validate_references throws exception when cid refs file does not contain
    the expected pid."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        pid_ref_abs_path = store.get_refs_abs_path("pid", pid)
        store.create_path(os.path.dirname(pid_ref_abs_path))
        store._write_pid_refs_file(pid_ref_abs_path, cid)
        store._write_cid_refs_file(cid_ref_abs_path, "bad_pid")
        with pytest.raises(ValueError):
            store._validate_references(pid, cid)


def test_validate_references_cid_refs_file_with_multiple_refs_missing_pid(pids, store):
    """Test that validate_references throws exception when cid refs file with multiple
    references does not contain the expected pid."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        pid_ref_abs_path = store.get_refs_abs_path("pid", pid)
        store.create_path(os.path.dirname(pid_ref_abs_path))
        store._write_pid_refs_file(pid_ref_abs_path, cid)
        store.create_path(os.path.dirname(pid_ref_abs_path))
        store._write_cid_refs_file(cid_ref_abs_path, "bad_pid")

        cid_reference_list = [pid]
        for i in range(0, 5):
            store._update_cid_refs(cid_ref_abs_path, f"dou.test.{i}")
            cid_reference_list.append(f"dou.test.{i}")

        with pytest.raises(ValueError):
            store._validate_references(pid, cid)
