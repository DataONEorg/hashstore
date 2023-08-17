"""Test module for the Python client (Public API calls only)"""
import sys
import os
from pathlib import Path
from hashstore import client


def test_create_hashstore_via_client(tmp_path):
    """Test creating a HashStore through client app."""
    client_directory = os.getcwd() + "/src/hashstore"
    client_module_path = f"{client_directory}/client.py"
    client_test_store = f"{tmp_path}/clienths"
    create_hashstore_flag = "-chs"
    store_depth = "-dp=3"
    store_width = "-wp=2"
    store_algorithm = "-ap=SHA-256"
    store_namespace = "-nsp=http://www.ns.test/v1"

    # Add file path of HashStore to sys so modules can be discovered
    sys.path.append(client_directory)

    chs_args = [
        client_module_path,
        client_test_store,
        create_hashstore_flag,
        store_depth,
        store_width,
        store_algorithm,
        store_namespace,
    ]

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
