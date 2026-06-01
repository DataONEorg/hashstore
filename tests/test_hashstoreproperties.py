"""Test cases for FileHashStoreProperties"""

import pytest

import hashstore
import hashstore.hashstore


def test_defaults():
    p = hashstore.HashStoreProperties()
    assert p.store_width == 2
    assert p.store_depth == 3
    assert len(p.store_metadata_namespace) > 1
    assert p.store_algorithm == "sha256"
    assert len(p.store_default_algo_list) >= 1
    assert p.store_algorithm in p.store_default_algo_list


def test_from_dict():
    """Veryify initialization from a dict of values."""
    props = {
        "store_width": 2,
        "store_depth": 3,
        "store_algorithm": "SHA-256",
        "store_default_algo_list": [
            "MD5",
        ],
    }
    p = hashstore.HashStoreProperties.from_dict(props)
    assert p.store_width == props["store_width"]
    assert p.store_depth == props["store_depth"]
    assert p.store_algorithm == hashstore.hashstore.from_dataone_algorithm_name(
        props["store_algorithm"]
    )
    assert len(p.store_default_algo_list) == 2
    assert p.store_algorithm in p.store_default_algo_list


def test_from_yaml(tmp_path):
    """Verify storing and loading a YAML file"""
    props = {
        "store_width": 2,
        "store_depth": 3,
        "store_algorithm": "SHA-256",
        "store_default_algo_list": [
            "MD5",
        ],
    }
    p = hashstore.HashStoreProperties.from_dict(props)
    yaml_path = tmp_path / "config.yaml"
    p.to_yaml(yaml_path)
    p2 = hashstore.HashStoreProperties.from_yaml(yaml_path)
    assert p == p2


def test_invalid_properties():
    """Test initialization with various invalid property values."""
    props = {
        "store_width": 256,
        "store_depth": 3,
        "store_algorithm": "SHA-256",
        "store_default_algo_list": [
            "MD5",
        ],
    }
    with pytest.raises(ValueError, match="store_width"):
        hashstore.HashStoreProperties.from_dict(props)
    props = {
        "store_width": 2,
        "store_depth": 30,
        "store_algorithm": "SHA-256",
        "store_default_algo_list": [
            "MD5",
        ],
    }
    with pytest.raises(ValueError, match="store_depth"):
        hashstore.HashStoreProperties.from_dict(props)
    props = {
        "store_width": 2,
        "store_depth": 3,
        "store_algorithm": "blake2s",
        "store_default_algo_list": [
            "MD5",
        ],
    }
    with pytest.raises(ValueError, match="algorithm"):
        hashstore.HashStoreProperties.from_dict(props)
    props = {
        "store_width": 2,
        "store_depth": 3,
        "store_algorithm": "SHA-256",
        "store_default_algo_list": [
            "foo",
        ],
    }
    with pytest.raises(ValueError, match="not available"):
        hashstore.HashStoreProperties.from_dict(props)
    props = {
        "store_width": 2,
        "store_depth": 3,
        "store_algorithm": "SHA-256",
        "store_default_algo_list": [
            "MD%",
        ],
        "store_metadata_namespace": None,
    }
    with pytest.raises(ValueError, match="store_metadata_namespace"):
        hashstore.HashStoreProperties.from_dict(props)
