# Core module for hashstore
from hashfs import HashFS
from pathlib import Path
import threading
import time
import hashlib
import importlib.metadata
import os
import fcntl


class HashStore:
    """Class representing the object store using hashes as keys"""

    # Class variables
    dir_depth = 3  # The number of directory levels for storing files
    dir_width = 2  # The width of the directory names, in characters
    SYSMETA_NS = "http://ns.dataone.org/service/types/v2.0"
    sysmeta_lock = threading.Lock()
    time_out = 1
    locked_pids = []
    supported_algorithms = [
        "md5",
        "sha1",
        "sha256",
        "sha384",
        "sha512",
        "sha224",
        "sha3_224",
        "sha3_256",
        "sha3_384",
        "sha3_512",
        "blake2b",
        "blake2s",
    ]

    def version(self):
        """Return the version number"""
        __version__ = importlib.metadata.version("hashstore")
        return __version__

    def __init__(self, store_path):
        """initialize the hashstore"""
        self.store_path = store_path
        self.objects = HashFS(
            self.store_path + "/objects",
            depth=self.dir_depth,
            width=self.dir_width,
            algorithm="sha256",
        )
        self.sysmeta = HashFS(
            self.store_path + "/sysmeta",
            depth=self.dir_depth,
            width=self.dir_width,
            algorithm="sha256",
        )
        self.tmp = HashFS(
            self.store_path + "/tmp",
            depth=self.dir_depth,
            width=self.dir_width,
            algorithm="sha256",
        )
        return None

    def store_object(self, data, algorithm="sha256", checksum=None):
        """Add a data object to the store. If the object is not a duplicate,
        a dictionary containing hash algorithms and their hex digest values will be
        returned. The supported algorithms list is based on algorithms supported in
        hashlib for Python 3.9. If an algorithm is passed that is supported, the hex
        digest dictionary returned will include the additional algorithm & hex digest.

        Default algorithms and hex digests to return: md5, sha1, sha256, sha384, sha512
        """
        algorithm = algorithm.lower().replace("-", "")
        if algorithm not in self.supported_algorithms:
            raise ValueError("Algorithm not supported")
        else:
            hex_digest_dict = self._add_object(
                data, algorithm=algorithm, checksum=checksum
            )
        return hex_digest_dict

    def store_sysmeta(self, pid, sysmeta, cid):
        """Add a system metadata object to the store. Returns the sysmeta content
        identifier (s_cid) which is the address of the sysmeta document. Multiple calls
        to this method are non-blocking and will be executed in parallel using locked_pids
        for synchronization.
        """
        while pid in self.locked_pids:
            try:
                time.sleep(self.time_out)
            except Exception as err:
                print(f"Unexpected {err=}, {type(err)=}")
                raise
        with self.sysmeta_lock:
            self.locked_pids.append(pid)
        try:
            sysmeta_cid = self._set_sysmeta(pid, sysmeta, cid)
        except Exception as err:
            print(f"Unexpected {err=}, {type(err)=}")
            raise
        finally:
            with self.sysmeta_lock:
                self.locked_pids.remove(pid)
        return sysmeta_cid

    def retrieve_object(self, pid):
        """Returns the sysmeta and a buffered stream of a cid obj given a persistent
        identifier (pid)."""
        sys_content = self._get_sysmeta(pid)
        cid = sys_content[0][:64]
        sysmeta = sys_content[1]
        c_stream = self.objects.open(cid)
        return sysmeta, c_stream

    def retrieve_sysmeta(self, pid):
        """Returns the sysmeta of a given persistent identifier (pid)."""
        sysmeta = self._get_sysmeta(pid)[1]
        return sysmeta

    def delete_object(self, pid):
        """Deletes an object given the pid."""
        s_content = self._get_sysmeta(pid)
        cid = s_content[0][:64]
        self.objects.delete(cid)

    def delete_sysmeta(self, pid):
        """Deletes a sysmeta document given the pid."""
        s_cid = self._hash_string(pid)
        self.sysmeta.delete(s_cid)

    def get_hex_digest(self, pid, algorithm):
        """Returns the hex digest based on the hash algorithm passed with a given pid"""
        s_cid = self._hash_string(pid)
        if not self.sysmeta.exists(s_cid):
            raise ValueError(f"No sysmeta found for pid: {pid}")
        if algorithm not in self.supported_algorithms:
            raise ValueError(f"Algorithm not supported: {algorithm}")
        s_content = self._get_sysmeta(pid)
        cid_get = s_content[0][:64]
        c_stream = self.objects.open(cid_get)
        hex_digest = self.objects.computehash(c_stream, algorithm=algorithm)
        return hex_digest

    def _add_object(self, data, algorithm, checksum):
        """Add a data blob to the store."""
        address = self.objects.put(data, algorithm=algorithm, checksum=checksum)
        if address.is_duplicate:
            return None
        return address.hex_digests

    def _set_sysmeta(self, pid, sysmeta, obj_cid):
        """Add a sysmeta document to the store."""
        s_cid = self._hash_string(pid)
        rel_path = self._rel_path(s_cid)
        full_path = Path(self.store_path) / "sysmeta" / rel_path
        try:
            sysmeta_path_tmp = ""
            if self.sysmeta.exists(s_cid):
                # Rename existing s_cid
                sysmeta_path = self.sysmeta.realpath(s_cid)
                sysmeta_path_tmp = sysmeta_path + ".tmp"
                os.rename(sysmeta_path, sysmeta_path_tmp)
            parent = full_path.parent
            parent.mkdir(parents=True, exist_ok=True)
            with full_path.open(mode="wb") as file:
                file.write(obj_cid.encode("utf-8"))
                format_id = " " + self.SYSMETA_NS
                file.write(format_id.encode("utf-8"))
                file.write(b"\x00")
                file.write(sysmeta)
            if self.sysmeta.exists(sysmeta_path_tmp):
                self.sysmeta.delete(sysmeta_path_tmp)
            return s_cid
        except Exception as err:
            print(f"Unexpected {err=}, {type(err)=}")
            if self.sysmeta.exists(sysmeta_path_tmp):
                if self.sysmeta.exists(s_cid):
                    self.delete_sysmeta(pid)
                    os.rename(sysmeta_path_tmp, sysmeta_path)
            raise

    def _get_sysmeta(self, pid):
        """Returns a list containing the sysmeta header and content given a persistent
        identifier (pid)."""
        s_cid = self._hash_string(pid)
        s_path = self.sysmeta.open(s_cid)
        s_content = s_path.read().decode("utf-8").split("\x00", 1)
        s_path.close()
        return s_content

    def _hash_string(self, input):
        """Calculate the SHA-256 digest for a string, and return it in a base64 hex
        encoded string."""
        hex = hashlib.sha256(input.encode("utf-8")).hexdigest()
        return hex

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
