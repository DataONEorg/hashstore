"""Test module for HashAddress"""
from hashstore.hashaddress import HashAddress


def test_hashaddress():
    """Test class returns correct values via dot notation"""
    ab_id = "hashstoretest"
    rel_path = "rel/path/to/object"
    abs_path = "abs/path/to/object"
    is_duplicate = "false"
    hex_digest_dict = {
        "md5": "md5value",
        "sha1": "sha1value",
        "sha224": "sha224value",
        "sha256": "sha256value",
        "sha512": "sha512value",
    }
    hash_address = HashAddress(ab_id, rel_path, abs_path, is_duplicate, hex_digest_dict)
    assert hash_address.id == ab_id
    assert hash_address.relpath == rel_path
    assert hash_address.abspath == abs_path
    assert hash_address.is_duplicate == is_duplicate
    assert hash_address.hex_digests.get("md5") == hex_digest_dict["md5"]
    assert hash_address.hex_digests.get("sha1") == hex_digest_dict["sha1"]
    assert hash_address.hex_digests.get("sha224") == hex_digest_dict["sha224"]
    assert hash_address.hex_digests.get("sha256") == hex_digest_dict["sha256"]
    assert hash_address.hex_digests.get("sha512") == hex_digest_dict["sha512"]
