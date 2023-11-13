"""Test module for FileHashStore core, utility and supporting methods"""
import os
import pytest


def test_write_cid_refs_file(pids, store):
    """Test that write_cid_reference writes a reference file."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        store.write_cid_refs_file(cid_ref_abs_path, pid)
        assert os.path.exists(cid_ref_abs_path)


def test_write_cid_refs_file_content(pids, store):
    """Test that write_cid_ref_file writes the expected content."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        store.write_cid_refs_file(cid_ref_abs_path, pid)

        with open(cid_ref_abs_path, "r", encoding="utf8") as f:
            cid_ref_file_pid = f.read()

        assert pid == cid_ref_file_pid.strip()


def test_update_cid_refs_content(pids, store):
    """Test that update_cid_ref updates the ref file as expected."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        store.write_cid_refs_file(cid_ref_abs_path, pid)

        pid_other = "dou.test.1"
        store.update_cid_refs(cid_ref_abs_path, pid_other)

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
        store.write_cid_refs_file(cid_ref_abs_path, pid)

        cid_reference_list = [pid]
        for i in range(0, 5):
            store.update_cid_refs(cid_ref_abs_path, f"dou.test.{i}")
            cid_reference_list.append(f"dou.test.{i}")

        line_count = 0
        with open(cid_ref_abs_path, "r", encoding="utf8") as f:
            for _, line in enumerate(f, start=1):
                line_count += 1
                value = line.strip()
                assert value in cid_reference_list

        assert line_count == 6


def test_update_cid_refs_content_pid_exists(pids, store):
    """Test that update_cid_ref does not write pid if pid already exists"""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        store.write_cid_refs_file(cid_ref_abs_path, pid)
        with pytest.raises(ValueError):
            store.update_cid_refs(cid_ref_abs_path, pid)


def test_delete_cid_refs_pid(pids, store):
    """Test that delete_cid_refs_pid deletes the given pid from the ref file."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        store.write_cid_refs_file(cid_ref_abs_path, pid)

        pid_other = "dou.test.1"
        store.update_cid_refs(cid_ref_abs_path, pid_other)
        store.delete_cid_refs_pid(cid_ref_abs_path, pid)

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
        store.write_cid_refs_file(cid_ref_abs_path, pid)

        pid_other = "dou.test.1"
        store.update_cid_refs(cid_ref_abs_path, pid_other)
        with pytest.raises(ValueError):
            store.delete_cid_refs_pid(cid_ref_abs_path, "dou.not.found.1")


def test_delete_cid_refs_pid_file(pids, store):
    """Test that delete_cid_refs_file deletes a reference file."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        store.write_cid_refs_file(cid_ref_abs_path, pid)
        store.delete_cid_refs_pid(cid_ref_abs_path, pid)
        cid_refs_deleted = store.delete_cid_refs_file(cid_ref_abs_path)

        assert cid_refs_deleted
        assert not os.path.exists(cid_ref_abs_path)


def test_delete_cid_refs_pid_file_not_empty(pids, store):
    """Test that delete_cid_refs_file does not raise an exception when refs file
    is not empty."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        store.write_cid_refs_file(cid_ref_abs_path, pid)
        cid_refs_deleted = store.delete_cid_refs_file(cid_ref_abs_path)
        assert not cid_refs_deleted


def test_delete_cid_refs_pid_file_not_found(pids, store):
    """Test that delete_cid_refs_file raises an exception when refs file not found."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        with pytest.raises(FileNotFoundError):
            store.delete_cid_refs_file(cid_ref_abs_path)


def test_write_pid_refs_file(pids, store):
    """Test that write_pid_refs_file writes a reference file."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        pid_ref_abs_path = store.get_refs_abs_path("pid", pid)
        store.create_path(os.path.dirname(pid_ref_abs_path))
        store.write_pid_refs_file(pid_ref_abs_path, cid)
        assert os.path.exists(pid_ref_abs_path)


def test_write_pid_refs_file_content(pids, store):
    """Test that write_pid_refs_file writes the expected content."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        pid_ref_abs_path = store.get_refs_abs_path("pid", pid)
        store.create_path(os.path.dirname(pid_ref_abs_path))
        store.write_pid_refs_file(pid_ref_abs_path, cid)

        with open(pid_ref_abs_path, "r", encoding="utf8") as f:
            pid_refs_cid = f.read()

        assert cid == pid_refs_cid


def test_delete_pid_refs_file(pids, store):
    """Test that delete_pid_refs_file deletes a reference file."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        pid_ref_abs_path = store.get_refs_abs_path("pid", pid)
        store.create_path(os.path.dirname(pid_ref_abs_path))
        store.write_pid_refs_file(pid_ref_abs_path, cid)
        store.delete_pid_refs_file(pid_ref_abs_path)

        assert not os.path.exists(pid_ref_abs_path)


def test_delete_pid_refs_file_file_not_found(pids, store):
    """Test that delete_pid_refs_file raises an exception when refs file not found."""
    for pid in pids.keys():
        pid_ref_abs_path = store.get_refs_abs_path("pid", pid)
        with pytest.raises(FileNotFoundError):
            store.delete_cid_refs_file(pid_ref_abs_path)
