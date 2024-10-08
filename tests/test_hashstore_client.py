"""Test module for the Python client (Public API calls only)."""

import sys
import os
from pathlib import Path
from hashstore import hashstoreclient

# pylint: disable=W0212


def test_create_hashstore(tmp_path):
    """Test creating a HashStore through the client."""
    client_directory = os.getcwd() + "/src/hashstore"
    client_module_path = f"{client_directory}/client.py"
    client_test_store = f"{tmp_path}/clienths"
    create_hashstore_opt = "-chs"
    store_depth = "-dp=3"
    store_width = "-wp=2"
    store_algorithm = "-ap=SHA-256"
    store_namespace = "-nsp=http://www.ns.test/v1"
    chs_args = [
        client_module_path,
        client_test_store,
        create_hashstore_opt,
        store_depth,
        store_width,
        store_algorithm,
        store_namespace,
    ]

    # Add file path of HashStore to sys so modules can be discovered
    sys.path.append(client_directory)
    # Manually change sys args to simulate command line arguments
    sys.argv = chs_args
    hashstoreclient.main()

    hashstore_yaml = Path(client_test_store + "/hashstore.yaml")
    hashstore_object_path = Path(client_test_store + "/objects")
    hashstore_metadata_path = Path(client_test_store + "/metadata")
    hashstore_client_python_log = Path(client_test_store + "/python_client.log")
    assert os.path.exists(hashstore_yaml)
    assert os.path.exists(hashstore_object_path)
    assert os.path.exists(hashstore_metadata_path)
    assert os.path.exists(hashstore_client_python_log)


def test_get_checksum(capsys, store, pids):
    """Test calculating a hash via HashStore through client."""
    client_directory = os.getcwd() + "/src/hashstore"
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        store.store_object(pid, path)

        client_module_path = f"{client_directory}/client.py"
        test_store = str(store.root)
        get_checksum_opt = "-getchecksum"
        client_pid_arg = f"-pid={pid}"
        algo_arg = f"-algo={store.algorithm}"
        chs_args = [
            client_module_path,
            test_store,
            get_checksum_opt,
            client_pid_arg,
            algo_arg,
        ]

        # Add file path of HashStore to sys so modules can be discovered
        sys.path.append(client_directory)
        # Manually change sys args to simulate command line arguments
        sys.argv = chs_args
        hashstoreclient.main()

        capsystext = capsys.readouterr().out
        expected_output = (
            f"guid/pid: {pid}\n"
            + f"algorithm: {store.algorithm}\n"
            + f"Checksum/Hex Digest: {pids[pid][store.algorithm]}\n"
        )
        assert capsystext == expected_output


def test_store_object(store, pids):
    """Test storing objects to HashStore through client."""
    client_directory = os.getcwd() + "/src/hashstore"
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        client_module_path = f"{client_directory}/client.py"
        test_store = str(store.root)
        store_object_opt = "-storeobject"
        client_pid_arg = f"-pid={pid}"
        path = f'-path={test_dir + pid.replace("/", "_")}'
        chs_args = [
            client_module_path,
            test_store,
            store_object_opt,
            client_pid_arg,
            path,
        ]

        # Add file path of HashStore to sys so modules can be discovered
        sys.path.append(client_directory)
        # Manually change sys args to simulate command line arguments
        sys.argv = chs_args
        hashstoreclient.main()

        assert store._exists("objects", pids[pid][store.algorithm])


def test_store_metadata(capsys, store, pids):
    """Test storing metadata to HashStore through client."""
    client_directory = os.getcwd() + "/src/hashstore"
    test_dir = "tests/testdata/"
    namespace = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    entity = "metadata"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        client_module_path = f"{client_directory}/client.py"
        test_store = str(store.root)
        store_metadata_opt = "-storemetadata"
        client_pid_arg = f"-pid={pid}"
        path = f"-path={syspath}"
        format_id = f"-formatid={namespace}"
        chs_args = [
            client_module_path,
            test_store,
            store_metadata_opt,
            client_pid_arg,
            path,
            format_id,
        ]

        # Add file path of HashStore to sys so modules can be discovered
        sys.path.append(client_directory)
        # Manually change sys args to simulate command line arguments
        sys.argv = chs_args
        hashstoreclient.main()

        metadata_directory = store._computehash(pid)
        metadata_document_name = store._computehash(pid + namespace)
        rel_path = Path(*store._shard(metadata_directory))
        full_path = (
            store._get_store_path("metadata") / rel_path / metadata_document_name
        )
        capsystext = capsys.readouterr().out
        expected_output = f"Metadata Path: {full_path}\n"
        assert capsystext == expected_output

    assert store._count(entity) == 3


def test_retrieve_objects(capsys, pids, store):
    """Test retrieving objects from a HashStore through client."""
    client_directory = os.getcwd() + "/src/hashstore"
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        store.store_object(pid, path)

        client_module_path = f"{client_directory}/client.py"
        test_store = str(store.root)
        delete_object_opt = "-retrieveobject"
        client_pid_arg = f"-pid={pid}"
        chs_args = [
            client_module_path,
            test_store,
            delete_object_opt,
            client_pid_arg,
        ]

        # Add file path of HashStore to sys so modules can be discovered
        sys.path.append(client_directory)
        # Manually change sys args to simulate command line arguments
        sys.argv = chs_args
        hashstoreclient.main()

        object_stream = store.retrieve_object(pid)
        object_content = (
            object_stream.read(1000).decode("utf-8")
            + "\n"
            + "...\n<-- Truncated for Display Purposes -->"
            + "\n"
        )
        object_stream.close()

        capsystext = capsys.readouterr().out
        assert capsystext == object_content


def test_retrieve_metadata(capsys, pids, store):
    """Test retrieving metadata from a HashStore through client."""
    client_directory = os.getcwd() + "/src/hashstore"
    test_dir = "tests/testdata/"
    namespace = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        _metadata_cid = store.store_metadata(pid, syspath, namespace)

        client_module_path = f"{client_directory}/client.py"
        test_store = str(store.root)
        retrieve_metadata_opt = "-retrievemetadata"
        client_pid_arg = f"-pid={pid}"
        format_id = f"-formatid={namespace}"
        chs_args = [
            client_module_path,
            test_store,
            retrieve_metadata_opt,
            client_pid_arg,
            format_id,
        ]

        # Add file path of HashStore to sys so modules can be discovered
        sys.path.append(client_directory)
        # Manually change sys args to simulate command line arguments
        sys.argv = chs_args
        hashstoreclient.main()

        metadata_stream = store.retrieve_metadata(pid, namespace)
        metadata_content = (
            metadata_stream.read(1000).decode("utf-8")
            + "\n"
            + "...\n<-- Truncated for Display Purposes -->"
            + "\n"
        )
        metadata_stream.close()

        capsystext = capsys.readouterr().out
        assert capsystext == metadata_content


def test_delete_objects(pids, store):
    """Test deleting objects from a HashStore through client."""
    client_directory = os.getcwd() + "/src/hashstore"
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = test_dir + pid.replace("/", "_")
        store.store_object(pid, path)

        client_module_path = f"{client_directory}/client.py"
        test_store = str(store.root)
        delete_object_opt = "-deleteobject"
        client_pid_arg = f"-pid={pid}"
        chs_args = [
            client_module_path,
            test_store,
            delete_object_opt,
            client_pid_arg,
        ]

        # Add file path of HashStore to sys so modules can be discovered
        sys.path.append(client_directory)
        # Manually change sys args to simulate command line arguments
        sys.argv = chs_args
        hashstoreclient.main()

        assert not store._exists("objects", pids[pid][store.algorithm])


def test_delete_metadata(pids, store):
    """Test deleting metadata from a HashStore through client."""
    client_directory = os.getcwd() + "/src/hashstore"
    test_dir = "tests/testdata/"
    namespace = "https://ns.dataone.org/service/types/v2.0#SystemMetadata"
    for pid in pids.keys():
        filename = pid.replace("/", "_") + ".xml"
        syspath = Path(test_dir) / filename
        _metadata_cid = store.store_metadata(pid, syspath, namespace)

        client_module_path = f"{client_directory}/client.py"
        test_store = str(store.root)
        delete_metadata_opt = "-deletemetadata"
        client_pid_arg = f"-pid={pid}"
        format_id = f"-formatid={namespace}"
        chs_args = [
            client_module_path,
            test_store,
            delete_metadata_opt,
            client_pid_arg,
            format_id,
        ]

        # Add file path of HashStore to sys so modules can be discovered
        sys.path.append(client_directory)
        # Manually change sys args to simulate command line arguments
        sys.argv = chs_args
        hashstoreclient.main()

        assert not store._exists("metadata", pids[pid]["metadata_cid"])
