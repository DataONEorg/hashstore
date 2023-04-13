# Core module for hashstore
from hashfs import HashFS
from hashfs.hashfs import Stream
from pathlib import Path
from contextlib import closing
from tempfile import NamedTemporaryFile
from collections import namedtuple
import shutil
import threading
import time
import hashlib
import importlib.metadata
import os


class HashStore:
    """Class representing the object store using hashes as keys"""

    # Class variables
    dir_depth = 3  # The number of directory levels for storing files
    dir_width = 2  # The width of the directory names, in characters
    SYSMETA_NS = "http://ns.dataone.org/service/types/v2.0"
    sysmeta_lock = threading.Lock()
    time_out_sec = 1
    locked_pids = []

    def version(self):
        """Return the version number"""
        __version__ = importlib.metadata.version("hashstore")
        return __version__

    def __init__(self, store_path):
        """initialize the hashstore"""
        self.store_path = store_path
        self.objects = HashFSExt(
            self.store_path + "/objects",
            depth=self.dir_depth,
            width=self.dir_width,
            algorithm="sha256",
        )
        self.sysmeta = HashFSExt(
            self.store_path + "/sysmeta",
            depth=self.dir_depth,
            width=self.dir_width,
            algorithm="sha256",
        )
        self.tmp = HashFSExt(
            self.store_path + "/tmp",
            depth=self.dir_depth,
            width=self.dir_width,
            algorithm="sha256",
        )
        return None

    def store_object(self, pid, data, algorithm="sha256", checksum=None):
        """Add a data object to the store. Returns a HashAddress object that contains
        the permanent address, relative file path, absolute file path, duplicate file
        boolean and hex digest dictionary. The supported algorithms list is based on
        algorithms supported in hashlib for Python 3.9. If an algorithm is passed that
        is supported, the hex digest dictionary returned will include the additional
        algorithm & hex digest.

        Default algorithms and hex digests to return: md5, sha1, sha256, sha384, sha512
        """
        algorithm = self._clean_algorithm(algorithm)
        if (
            algorithm not in self.objects.default_algo_list
            and algorithm not in self.objects.other_algo_list
        ):
            raise ValueError(f"Algorithm not supported: {algorithm}")
        else:
            hash_address = self._add_object(
                pid, data, algorithm=algorithm, checksum=checksum
            )
        return hash_address

    def store_sysmeta(self, pid, sysmeta):
        """Add a system metadata object to the store. Returns the sysmeta content
        identifier (s_cid) which is the address of the sysmeta document. Multiple calls
        to this method are non-blocking and will be executed in parallel using locked_pids
        for synchronization.
        """
        # Wait for the pid to release if it's in use
        while pid in self.locked_pids:
            time.sleep(self.time_out_sec)
        # Modify locked_pids consecutively
        with self.sysmeta_lock:
            self.locked_pids.append(pid)
        try:
            sysmeta_cid = self._set_sysmeta(pid, sysmeta)
        finally:
            # Release pid
            with self.sysmeta_lock:
                self.locked_pids.remove(pid)
        return sysmeta_cid

    def retrieve_object(self, pid):
        """Returns the sysmeta and a buffered stream of a pid_hash given a persistent
        identifier (pid)."""
        pid_hash = self.objects._get_sha256_hex_digest(pid)
        s_cid_exists = self.sysmeta.exists(pid_hash)
        if s_cid_exists:
            sys_content = self._get_sysmeta(pid)
            sysmeta = sys_content[1]
            c_stream = self.objects.open(pid_hash)
        else:
            raise ValueError(f"No sysmeta found for pid: {pid}")
        return sysmeta, c_stream

    def retrieve_sysmeta(self, pid):
        """Returns the sysmeta of a given persistent identifier (pid)."""
        pid_hash = self.sysmeta._get_sha256_hex_digest(pid)
        s_cid_exists = self.sysmeta.exists(pid_hash)
        if s_cid_exists:
            sysmeta = self._get_sysmeta(pid)[1]
        else:
            raise ValueError(f"No sysmeta found for pid: {pid}")
        return sysmeta

    def delete_object(self, pid):
        """Deletes an object given the pid."""
        pid_hash = self.objects._get_sha256_hex_digest(pid)
        self.objects.delete(pid_hash)
        return True

    def delete_sysmeta(self, pid):
        """Deletes a sysmeta document given the pid."""
        pid_hash = self.sysmeta._get_sha256_hex_digest(pid)
        self.sysmeta.delete(pid_hash)
        return True

    def get_hex_digest(self, pid, algorithm):
        """Returns the hex digest based on the hash algorithm passed with a given pid"""
        algorithm = self._clean_algorithm(algorithm)
        pid_hash = self.sysmeta._get_sha256_hex_digest(pid)
        if not self.sysmeta.exists(pid_hash):
            raise ValueError(f"No sysmeta found for pid: {pid}")
        if (
            algorithm not in self.sysmeta.default_algo_list
            and algorithm not in self.sysmeta.other_algo_list
        ):
            raise ValueError(f"Algorithm not supported: {algorithm}")
        s_content = self._get_sysmeta(pid)
        cid_get = s_content[0][:64]
        c_stream = self.objects.open(cid_get)
        hex_digest = self.objects.computehash(c_stream, algorithm=algorithm)
        return hex_digest

    def _add_object(self, pid, data, algorithm, checksum):
        """Add a data blob to the store."""
        address = self.objects.put(pid, data, algorithm=algorithm, checksum=checksum)
        # Caller to handle address.is_duplicate is true
        return address

    def _set_sysmeta(self, pid, sysmeta):
        """Add a sysmeta document to the store."""
        pid_hash = self.sysmeta._get_sha256_hex_digest(pid)
        rel_path = self._rel_path(pid_hash)
        full_path = self.sysmeta._get_store_path() / rel_path

        # If sysmeta exists, it is an update request
        sysmeta_path_tmp = ""
        sysmeta_path = ""
        sysmeta_path_tmp = ""
        try:
            if self.sysmeta.exists(pid_hash):
                sysmeta_path = self.sysmeta.realpath(pid_hash)
                sysmeta_path_tmp = sysmeta_path + ".tmp"
                # Delete .tmp file if it already exists
                if self.sysmeta.exists(sysmeta_path_tmp):
                    self.sysmeta.delete(sysmeta_path_tmp)
                # Rename existing s_cid
                os.rename(sysmeta_path, sysmeta_path_tmp)
        except Exception as err:
            print(f"Unexpected {err=}, {type(err)=}")
            if not self.sysmeta.exists(pid_hash) and self.sysmeta.exists(
                sysmeta_path_tmp
            ):
                os.rename(sysmeta_path_tmp, sysmeta_path)
            raise

        # Write new sysmeta
        try:
            parent = full_path.parent
            parent.mkdir(parents=True, exist_ok=True)
            with full_path.open(mode="wb") as file:
                file.write(pid_hash.encode("utf-8"))
                format_id = " " + self.SYSMETA_NS
                file.write(format_id.encode("utf-8"))
                file.write(b"\x00")
                file.write(sysmeta)
            if self.sysmeta.exists(sysmeta_path_tmp):
                self.sysmeta.delete(sysmeta_path_tmp)
            return pid_hash
        except Exception as err:
            print(f"Unexpected {err=}, {type(err)=}")
            # Abort process for any exception and restore existing sysmeta object
            if self.sysmeta.exists(sysmeta_path_tmp):
                if self.sysmeta.exists(pid_hash):
                    self.sysmeta.delete(pid_hash)
                os.rename(sysmeta_path_tmp, sysmeta_path)
            else:
                if self.sysmeta.exists(pid_hash):
                    self.sysmeta.delete(pid_hash)
            raise

    def _get_sysmeta(self, pid):
        """Returns a list containing the sysmeta header and content given a persistent
        identifier (pid)."""
        pid_hash = self.sysmeta._get_sha256_hex_digest(pid)
        s_path = self.sysmeta.open(pid_hash)
        s_content = s_path.read().decode("utf-8").split("\x00", 1)
        s_path.close()
        return s_content

    def _rel_path(self, hash):
        """Return the storage path for a given hash hexdigest."""
        chunks = []
        for i in range(self.dir_depth):
            temp = hash[: self.dir_width]
            hash = hash[self.dir_width :]
            chunks.append(temp)
            if i == self.dir_depth - 1:
                chunks.append(hash)
        return "/".join(chunks)

    def _clean_algorithm(self, algorithm_string):
        """Return a string that is compatible with generating a new hashlib library
        hashing object"""
        count = 0
        for char in algorithm_string:
            if char.isdigit():
                count += 1
        if count > 3:
            cleaned_string = algorithm_string.lower().replace("-", "_")
        else:
            cleaned_string = algorithm_string.lower().replace("-", "").replace("_", "")
        return cleaned_string


class HashFSExt(HashFS):
    """A subclass of HashFS with extended methods to support the returning of a
    dictionary consisting of algorithms (based on the most common algorithm types
    currently used in Metacat) and their respective hex digests."""

    # Class variables
    default_algo_list = ["sha1", "sha256", "sha384", "sha512", "md5"]
    other_algo_list = [
        "sha224",
        "sha3_224",
        "sha3_256",
        "sha3_384",
        "sha3_512",
        "blake2b",
        "blake2s",
    ]

    def computehash(self, stream, algorithm=None):
        """Compute hash of a file-like object using :attr:`algorithm` by default
        or with optional algorithm supported."""
        if algorithm is None:
            hashobj = hashlib.new(self.algorithm)
        else:
            hashobj = hashlib.new(algorithm)
        for data in stream:
            hashobj.update(self._to_bytes(data))
        return hashobj.hexdigest()

    def put(self, pid, file, extension=None, algorithm=None, checksum=None):
        """Store contents of `file` on disk using its content hash for the
        address.

        Args:
            file (mixed): Readable object or path to file.
            extension (str, optional): Optional extension to append to file
                when saving.
            algorithm (str, optional): Optional algorithm value to include
                when returning hex digests.
            checksum (str, optional): Optional checksum to validate object
                against hex digest before moving to permanent location.

        Returns:
            HashAddress: File's hash address.
        """
        stream = Stream(file)

        with closing(stream):
            id, hex_digest_dict, filepath, is_duplicate = self._move_and_get_checksums(
                pid, stream, extension, algorithm, checksum
            )

        return HashAddress(
            id, self.relpath(filepath), filepath, is_duplicate, hex_digest_dict
        )

    def _move_and_get_checksums(
        self, pid, stream, extension=None, algorithm=None, checksum=None
    ):
        """Copy the contents of `stream` onto disk with an optional file
        extension appended. The copy process uses a temporary file to store the
        initial contents and returns a dictionary of algorithms and their
        hex digest values. Once the file has been determined not to exist/be a
        duplicate, it then moves that file to its final location. If an algorithm
        and checksum is provided, it will proceed to validate the object and
        delete the file if the hex digest stored does not match what is provided.
        """

        # Create temporary file and calculate hex digests
        hex_digests, fname = self._mktempfile(stream, algorithm)
        id = self._get_sha256_hex_digest(pid)

        filepath = self.idpath(id, extension)
        self.makepath(os.path.dirname(filepath))

        # Only move file if it doesn't already exist.
        if not os.path.isfile(filepath):
            if algorithm is not None and checksum is not None:
                hex_digest_stored = hex_digests[algorithm]
                if hex_digest_stored != checksum:
                    self.delete(fname)
                    raise ValueError(
                        f"Hex digest and checksum do not match - file not stored. Algorithm: {algorithm}. Checksum provided: {checksum} != Hex Digest: {hex_digest_stored}"
                    )
            is_duplicate = False
            try:
                shutil.move(fname, filepath)
            except Exception as err:
                # Revert storage process for the time being for any failure
                # TODO: Discuss handling of permissions, memory and storage exceptions
                print(f"Unexpected {err=}, {type(err)=}")
                if os.path.isfile(filepath):
                    self.delete(filepath)
                self.delete(fname)
                raise Exception(
                    f"Aborting Upload - an unexpected error has occurred when moving file: {id} - Error: {err}"
                )
        else:
            # Else delete temporary file
            is_duplicate = True
            self.delete(fname)

        return id, hex_digests, filepath, is_duplicate

    def _mktempfile(self, stream, algorithm=None):
        """Create a named temporary file from a :class:`Stream` object and
        return its filename and a dictionary of its algorithms and hex digests.
        If an algorithm is provided, it will add the respective hex digest to
        the dictionary.
        """
        tmp = NamedTemporaryFile(delete=False)

        # Ensure tmp file is created with desired permissions
        if self.fmode is not None:
            oldmask = os.umask(0)
            try:
                os.chmod(tmp.name, self.fmode)
            finally:
                os.umask(oldmask)

        # Hash objects to digest
        if algorithm is not None and algorithm in self.other_algo_list:
            self.default_algo_list.append(algorithm)
        if algorithm is not None and algorithm not in self.default_algo_list:
            raise ValueError(f"Algorithm not supported: {algorithm}")

        hash_algorithms = [
            hashlib.new(algorithm) for algorithm in self.default_algo_list
        ]

        # tmp is a file-like object that is already opened for writing by default
        with tmp as tmp_file:
            for data in stream:
                tmp_file.write(self._to_bytes(data))
                for hash_algorithm in hash_algorithms:
                    hash_algorithm.update(self._to_bytes(data))

        hex_digest_list = [
            hash_algorithm.hexdigest() for hash_algorithm in hash_algorithms
        ]
        hex_digest_dict = dict(zip(self.default_algo_list, hex_digest_list))

        return hex_digest_dict, tmp.name

    def _to_bytes(self, text):
        """Convert text to sequence of bytes using utf-8 encoding"""
        if not isinstance(text, bytes):
            text = bytes(text, "utf8")
        return text

    def _get_store_path(self):
        """Return a path object of the root directory of the store."""
        return Path(self.root)

    def _get_sha256_hex_digest(self, input):
        """Calculate the SHA-256 digest for a string, and return it in a base64 hex
        encoded string."""
        hex = hashlib.sha256(input.encode("utf-8")).hexdigest()
        return hex


class HashAddress(
    namedtuple(
        "HashAddress", ["id", "relpath", "abspath", "is_duplicate", "hex_digests"]
    )
):
    """File address containing file's path on disk and its content hash ID.

    Attributes:
        id (str): Hash ID (hexdigest) of file contents.
        relpath (str): Relative path location to :attr:`HashFS.root`.
        abspath (str): Absoluate path location of file on disk.
        is_duplicate (boolean, optional): Whether the hash address created was
            a duplicate of a previously existing file. Can only be ``True``
            after a put operation. Defaults to ``False``.
        hex_digests (dict, optional): A list of hex digests to validate objects (md5, sha1,
            sha256, sha384, sha512)
    """

    def __new__(cls, id, relpath, abspath, is_duplicate=False, hex_digests={}):
        return super(HashAddress, cls).__new__(
            cls, id, relpath, abspath, is_duplicate, hex_digests
        )
