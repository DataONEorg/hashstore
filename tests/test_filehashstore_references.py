"""Test module for FileHashStore's reference system to tag stored objects."""
import os
import shutil
import pytest

# pylint: disable=W0212


def test_tag_object(pids, store):
    """Test tag object returns boolean."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(None, path)
        object_tagged = store.tag_object(pid, object_metadata.id)
        assert object_tagged


def test_tag_object_pid_refs_file(pids, store):
    """Test tag object creates the pid reference file."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(None, path)
        store.tag_object(pid, object_metadata.id)
        pid_refs_file_path = store.get_refs_abs_path("pid", pid)
        assert os.path.exists(pid_refs_file_path)


def test_tag_object_pid_refs_file_exists(pids, store):
    """Test tag object throws exception when pid refs file already exists."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(None, path)
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
        object_metadata = store.store_object(None, path)
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
        object_metadata = store.store_object(None, path)
        cid = object_metadata.id
        store.tag_object(pid, object_metadata.id)
        cid_refs_file_path = store.get_refs_abs_path("cid", cid)
        assert os.path.exists(cid_refs_file_path)


def test_tag_object_cid_refs_file_content(pids, store):
    """Test tag object tags cid reference file successfully with pid."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(None, path)
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
        object_metadata = store.store_object(None, path)
        store.tag_object(pid, object_metadata.id)
        another_cid = "dou.test.1"
        with pytest.raises(FileExistsError):
            store.tag_object(pid, another_cid)

        second_cid_hash = store.get_refs_abs_path("cid", another_cid)
        assert not os.path.exists(second_cid_hash)


def test_tag_object_cid_refs_update_cid_refs_updated(store):
    """Test tag object updates a cid reference file that already exists."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid.replace("/", "_")
    # Store data only
    object_metadata = store.store_object(None, path)
    cid = object_metadata.id
    # Tag object
    store.tag_object(pid, cid)
    # Tag the cid with another pid
    additional_pid = "dou.test.1"
    store.tag_object(additional_pid, cid)

    # Read cid file to confirm cid refs file contains the additional pid
    cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
    with open(cid_ref_abs_path, "r", encoding="utf8") as f:
        for _, line in enumerate(f, start=1):
            value = line.strip()
            assert value == pid or value == additional_pid


def test_tag_object_cid_refs_update_pid_refs_created(store):
    """Test tag object creates a pid reference file when called to tag an object
    that already exists."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid.replace("/", "_")
    # Store data only
    object_metadata = store.store_object(None, path)
    cid = object_metadata.id
    # Tag object
    store.tag_object(pid, cid)
    # Tag the cid with another pid
    additional_pid = "dou.test.1"
    store.tag_object(additional_pid, cid)

    pid_refs_file_path = store.get_refs_abs_path("pid", additional_pid)
    assert os.path.exists(pid_refs_file_path)


def test_tag_object_cid_refs_update_pid_found_but_file_missing(store):
    """Test that tag_object creates a missing pid refs file that somehow disappeared
    when called to tag a cid that already contains the pid."""
    test_dir = "tests/testdata/"
    pid = "jtao.1700.1"
    path = test_dir + pid.replace("/", "_")
    object_metadata = store.store_object(None, path)
    store.tag_object(pid, object_metadata.id)
    cid = object_metadata.id
    # Manually update the cid refs, pid refs file missing at this point
    additional_pid = "dou.test.1"
    cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
    store._update_cid_refs(cid_ref_abs_path, additional_pid)

    # Confirm the pid refs file is missing
    pid_refs_file_path = store.get_refs_abs_path("pid", additional_pid)
    assert not os.path.exists(pid_refs_file_path)

    # Call tag_object, this should create the missing pid refs file
    store.tag_object(additional_pid, cid)

    # Confirm it has been created
    assert os.path.exists(pid_refs_file_path)


def test_verify_object(pids, store):
    """Test verify object succeeds given good arguments."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(data=path)
        checksum = object_metadata.hex_digests.get(store.algorithm)
        checksum_algorithm = store.algorithm
        expected_file_size = object_metadata.obj_size
        store.verify_object(
            object_metadata, checksum, checksum_algorithm, expected_file_size
        )


def test_verify_object_exception_incorrect_object_metadata_type(pids, store):
    """Test verify object raises exception when incorrect object is given to
    object_metadata arg."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(data=path)
        checksum = object_metadata.hex_digests.get(store.algorithm)
        checksum_algorithm = store.algorithm
        expected_file_size = object_metadata.obj_size
        with pytest.raises(ValueError):
            store.verify_object(
                "bad_type", checksum, checksum_algorithm, expected_file_size
            )


def test_verify_object_exception_incorrect_size(pids, store):
    """Test verify object raises exception when incorrect size is supplied."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(data=path)
        checksum = object_metadata.hex_digests.get(store.algorithm)
        checksum_algorithm = store.algorithm
        with pytest.raises(ValueError):
            store.verify_object(object_metadata, checksum, checksum_algorithm, 1000)

        cid = object_metadata.id
        cid = object_metadata.hex_digests[store.algorithm]
        cid_abs_path = store.get_refs_abs_path("cid", cid)
        assert not os.path.exists(cid_abs_path)


def test_verify_object_exception_incorrect_checksum(pids, store):
    """Test verify object raises exception when incorrect checksum is supplied."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(data=path)
        cid = object_metadata.id
        store.tag_object(pid, cid)
        checksum_algorithm = store.algorithm
        expected_file_size = object_metadata.obj_size
        with pytest.raises(ValueError):
            store.verify_object(
                object_metadata, "abc123", checksum_algorithm, expected_file_size
            )

        cid = object_metadata.id
        cid = object_metadata.hex_digests[store.algorithm]
        cid_abs_path = store.get_refs_abs_path("cid", cid)
        assert not os.path.exists(cid_abs_path)


def test_verify_object_exception_incorrect_checksum_algo(pids, store):
    """Test verify object raises exception when incorrect algorithm is supplied."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(data=path)
        checksum = object_metadata.hex_digests.get(store.algorithm)
        expected_file_size = object_metadata.obj_size
        with pytest.raises(ValueError):
            store.verify_object(object_metadata, checksum, "md2", expected_file_size)


def test_write_cid_refs_file(store):
    """Test that write_cid_reference writes a reference file."""
    tmp_root_path = store.get_store_path("refs") / "tmp"
    tmp_cid_refs_file = store._write_cid_refs_file(tmp_root_path, "test_pid")
    assert os.path.exists(tmp_cid_refs_file)


def test_write_cid_refs_file_content(pids, store):
    """Test that write_cid_ref_file writes the expected content."""
    for pid in pids.keys():
        tmp_root_path = store.get_store_path("refs") / "tmp"
        tmp_cid_refs_file = store._write_cid_refs_file(tmp_root_path, pid)
        with open(tmp_cid_refs_file, "r", encoding="utf8") as f:
            cid_ref_file_pid = f.read()

        assert pid == cid_ref_file_pid.strip()


def test_update_cid_refs_content(pids, store):
    """Test that update_cid_ref updates the ref file as expected."""
    for pid in pids.keys():
        tmp_root_path = store.get_store_path("refs") / "tmp"
        tmp_cid_refs_file = store._write_cid_refs_file(tmp_root_path, pid)
        pid_other = "dou.test.1"
        store._update_cid_refs(tmp_cid_refs_file, pid_other)

        with open(tmp_cid_refs_file, "r", encoding="utf8") as f:
            for _, line in enumerate(f, start=1):
                value = line.strip()
                assert value == pid or value == pid_other


def test_update_cid_refs_content_multiple(pids, store):
    """Test that update_cid_refs adds multiple references successfully."""
    for pid in pids.keys():
        tmp_root_path = store.get_store_path("refs") / "tmp"
        tmp_cid_refs_file = store._write_cid_refs_file(tmp_root_path, pid)

        cid_reference_list = [pid]
        for i in range(0, 5):
            store._update_cid_refs(tmp_cid_refs_file, f"dou.test.{i}")
            cid_reference_list.append(f"dou.test.{i}")

        line_count = 0
        with open(tmp_cid_refs_file, "r", encoding="utf8") as f:
            for _, line in enumerate(f, start=1):
                line_count += 1
                value = line.strip()
                assert value in cid_reference_list

        assert line_count == 6


def test_update_cid_refs_content_pid_exists(pids, store):
    """Test that update_cid_ref does not throw exception if pid already exists
    and proceeds to complete the tagging process (verify_object)"""
    for pid in pids.keys():
        tmp_root_path = store.get_store_path("refs") / "tmp"
        tmp_cid_refs_file = store._write_cid_refs_file(tmp_root_path, pid)
        # Exception should not be thrown
        store._update_cid_refs(tmp_cid_refs_file, pid)


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
        tmp_root_path = store.get_store_path("refs") / "tmp"
        tmp_cid_refs_file = store._write_cid_refs_file(tmp_root_path, pid)

        pid_other = "dou.test.1"
        store._update_cid_refs(tmp_cid_refs_file, pid_other)
        store._delete_cid_refs_pid(tmp_cid_refs_file, pid)

        with open(tmp_cid_refs_file, "r", encoding="utf8") as f:
            for _, line in enumerate(f, start=1):
                value = line.strip()
                print(value)
                assert value == pid_other


def test_delete_cid_refs_pid_file(pids, store):
    """Test that delete_cid_refs_pid leaves a file empty when removing the last pid."""
    for pid in pids.keys():
        tmp_root_path = store.get_store_path("refs") / "tmp"
        tmp_cid_refs_file = store._write_cid_refs_file(tmp_root_path, pid)
        # First remove the pid
        store._delete_cid_refs_pid(tmp_cid_refs_file, pid)

        assert os.path.getsize(tmp_cid_refs_file) == 0


def test_write_pid_refs_file(pids, store):
    """Test that write_pid_refs_file writes a reference file."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        tmp_root_path = store.get_store_path("refs") / "tmp"
        tmp_pid_refs_file = store._write_pid_refs_file(tmp_root_path, cid)
        assert os.path.exists(tmp_pid_refs_file)


def test_write_pid_refs_file_content(pids, store):
    """Test that write_pid_refs_file writes the expected content."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        tmp_root_path = store.get_store_path("refs") / "tmp"
        tmp_pid_refs_file = store._write_pid_refs_file(tmp_root_path, cid)
        with open(tmp_pid_refs_file, "r", encoding="utf8") as f:
            pid_refs_cid = f.read()

        assert cid == pid_refs_cid


def test_delete_pid_refs_file(pids, store):
    """Test that delete_pid_refs_file deletes a reference file."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        tmp_root_path = store.get_store_path("refs") / "tmp"
        tmp_pid_refs_file = store._write_pid_refs_file(tmp_root_path, cid)
        store._delete_pid_refs_file(tmp_pid_refs_file)

        assert not os.path.exists(tmp_pid_refs_file)


def test_delete_pid_refs_file_file_not_found(pids, store):
    """Test that delete_pid_refs_file raises an exception when refs file not found."""
    for pid in pids.keys():
        pid_ref_abs_path = store.get_refs_abs_path("pid", pid)
        with pytest.raises(FileNotFoundError):
            store._delete_pid_refs_file(pid_ref_abs_path)


def test_verify_hashstore_references_pid_refs_file_missing(pids, store):
    """Test _verify_hashstore_references throws exception when pid refs file is missing."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        with pytest.raises(FileNotFoundError):
            store._verify_hashstore_references(pid, cid, "create")


def test_verify_hashstore_references_pid_refs_incorrect_cid(pids, store):
    """Test _verify_hashstore_references throws exception when pid refs file cid is incorrect."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        object_metadata = store.store_object(pid, path)
        cid = object_metadata.id

        # Place the wrong cid into the pid refs file that has already been created
        pid_ref_abs_path = store.get_refs_abs_path("pid", pid)
        with open(pid_ref_abs_path, "w", encoding="utf8") as pid_ref_file:
            pid_ref_file.seek(0)
            pid_ref_file.write("intentionally.wrong.pid")
            pid_ref_file.truncate()

        with pytest.raises(FileNotFoundError):
            store._verify_hashstore_references(pid, cid, "create")


def test_verify_hashstore_references_cid_refs_file_missing(pids, store):
    """Test _verify_hashstore_references throws exception when cid refs file is missing."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        pid_ref_abs_path = store.get_refs_abs_path("pid", pid)
        store.create_path(os.path.dirname(pid_ref_abs_path))
        tmp_root_path = store.get_store_path("refs") / "tmp"
        tmp_pid_refs_file = store._write_pid_refs_file(tmp_root_path, "bad_cid")
        shutil.move(tmp_pid_refs_file, pid_ref_abs_path)

        with pytest.raises(FileNotFoundError):
            store._verify_hashstore_references(pid, cid, "create")


def test_verify_hashstore_references_cid_refs_file_missing_pid(pids, store):
    """Test _verify_hashstore_references throws exception when cid refs file does not contain
    the expected pid."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        # Get a tmp cid refs file and write the wrong pid into it
        tmp_root_path = store.get_store_path("refs") / "tmp"
        tmp_cid_refs_file = store._write_cid_refs_file(tmp_root_path, "bad pid")
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        shutil.move(tmp_cid_refs_file, cid_ref_abs_path)
        # Now write the pid refs file, both cid and pid refs must be present
        pid_ref_abs_path = store.get_refs_abs_path("pid", pid)
        store.create_path(os.path.dirname(pid_ref_abs_path))
        tmp_root_path = store.get_store_path("refs") / "tmp"
        tmp_pid_refs_file = store._write_pid_refs_file(tmp_root_path, cid)
        shutil.move(tmp_pid_refs_file, pid_ref_abs_path)

        with pytest.raises(ValueError):
            store._verify_hashstore_references(pid, cid, "create")


def test_verify_hashstore_references_cid_refs_file_with_multiple_refs_missing_pid(
    pids, store
):
    """Test _verify_hashstore_references throws exception when cid refs file with multiple
    references does not contain the expected pid."""
    for pid in pids.keys():
        cid = pids[pid]["sha256"]
        # Write the wrong pid into a cid refs file and move it where it needs to be
        tmp_root_path = store.get_store_path("refs") / "tmp"
        tmp_cid_refs_file = store._write_cid_refs_file(tmp_root_path, "bad pid")
        cid_ref_abs_path = store.get_refs_abs_path("cid", cid)
        store.create_path(os.path.dirname(cid_ref_abs_path))
        shutil.move(tmp_cid_refs_file, cid_ref_abs_path)
        # Now write the pid refs with expected values
        pid_ref_abs_path = store.get_refs_abs_path("pid", pid)
        store.create_path(os.path.dirname(pid_ref_abs_path))
        tmp_root_path = store.get_store_path("refs") / "tmp"
        tmp_pid_refs_file = store._write_pid_refs_file(tmp_root_path, cid)
        shutil.move(tmp_pid_refs_file, pid_ref_abs_path)

        cid_reference_list = [pid]
        for i in range(0, 5):
            store._update_cid_refs(cid_ref_abs_path, f"dou.test.{i}")
            cid_reference_list.append(f"dou.test.{i}")

        with pytest.raises(ValueError):
            store._verify_hashstore_references(pid, cid, "create")
