"""Test module for FileHashStore's Stream class."""
import hashlib
import io
from pathlib import Path
import pytest
from hashstore.filehashstore import Stream


def test_stream_reads_file(pids):
    """Test that a stream can read a file and yield its contents."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path_string = test_dir + pid.replace("/", "_")
        obj_stream = Stream(path_string)
        hashobj = hashlib.new("sha256")
        for data in obj_stream:
            hashobj.update(data)
        hex_digest = hashobj.hexdigest()
        assert pids[pid]["sha256"] == hex_digest


def test_stream_reads_path_object(pids):
    """Test that a stream can read a file-like object and yield its contents."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path = Path(test_dir + pid.replace("/", "_"))
        obj_stream = Stream(path)
        hashobj = hashlib.new("sha256")
        for data in obj_stream:
            hashobj.update(data)
        hex_digest = hashobj.hexdigest()
        assert pids[pid]["sha256"] == hex_digest


def test_stream_returns_to_original_position_on_close(pids):
    """Test that a stream returns to its original position after closing the file."""
    test_dir = "tests/testdata/"
    for pid in pids.keys():
        path_string = test_dir + pid.replace("/", "_")
        input_stream = io.open(path_string, "rb")
        input_stream.seek(5)
        hashobj = hashlib.new("sha256")
        obj_stream = Stream(input_stream)
        for data in obj_stream:
            hashobj.update(data)
        obj_stream.close()
        assert input_stream.tell() == 5
        input_stream.close()


def test_stream_raises_error_for_invalid_object():
    """Test that a stream raises ValueError for an invalid input object."""
    with pytest.raises(ValueError):
        Stream(1234)
