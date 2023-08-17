"""Test module for the Python client (Public API calls only)"""
import multiprocessing
import sys
import os
from pathlib import Path
from hashstore import client


def test_create_hashstore(tmp_path):
    """Test creating a HashStore through the client."""
    client_directory = os.getcwd() + "/src/hashstore"
    client_module_path = f"{client_directory}/client.py"
    client_test_store = f"{tmp_path}/clienths"
    create_hashstore_flag = "-chs"
    store_depth = "-dp=3"
    store_width = "-wp=2"
    store_algorithm = "-ap=SHA-256"
    store_namespace = "-nsp=http://www.ns.test/v1"
    chs_args = [
        client_module_path,
        client_test_store,
        create_hashstore_flag,
        store_depth,
        store_width,
        store_algorithm,
        store_namespace,
    ]

    # Add file path of HashStore to sys so modules can be discovered
    sys.path.append(client_directory)

    # Manually change sys args to simulate command line arguments
    sys.argv = chs_args

    client.main()

    hashstore_yaml = Path(client_test_store + "/hashstore.yaml")
    hashstore_object_path = Path(client_test_store + "/objects")
    hashstore_metadata_path = Path(client_test_store + "/metadata")
    hashstore_client_python_log = Path(client_test_store + "/python_client.log")
    assert os.path.exists(hashstore_yaml)
    assert os.path.exists(hashstore_object_path)
    assert os.path.exists(hashstore_metadata_path)
    assert os.path.exists(hashstore_client_python_log)


def test_store_object_two(store):
    """Test storing an object to HashStore through client app."""
    client_directory = os.getcwd() + "/src/hashstore"
    client_module_path = f"{client_directory}/client.py"
    test_dir = "tests/testdata/"
    test_store = store.root
    store_object_flag = "-storeobject"
    pid = "jtao.1700.1"
    client_pid_arg = f"-pid={pid}"
    path = f'-path={test_dir + pid.replace("/", "_")}'
    chs_args = [
        client_module_path,
        test_store,
        store_object_flag,
        client_pid_arg,
        path,
    ]

    # Add file path of HashStore to sys so modules can be discovered
    sys.path.append(client_directory)

    # Manually change sys args to simulate command line arguments
    sys.argv = chs_args

    client.main()

    pid_sharded_path = (
        "a8/24/19/25740d5dcd719596639e780e0a090c9d55a5d0372b0eaf55ed711d4edf"
    )
    expected_pid_abs_path = Path(test_store + f"/objects/{pid_sharded_path}")
    assert os.path.exists(expected_pid_abs_path)
