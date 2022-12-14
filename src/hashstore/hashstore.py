# Core module for hashstore
from hashfs import HashFS
from pathlib import Path
import hashlib
import importlib.metadata


class HashStore:
    """Class representing the object store using hashes as keys"""

    # Class variables
    dir_depth = 3  # The number of directory levels for storing files
    dir_width = 2  # The width of the directory names, in characters
    SYSMETA_NS = "http://ns.dataone.org/service/types/v2.0"

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
        self.tags = HashFS(
            self.store_path + "/tags",
            depth=self.dir_depth,
            width=self.dir_width,
            algorithm="sha256",
        )
        return None

    def store(self, pid, sysmeta, data):
        """Add a data object and metadata to the store"""
        # TODO: decide if pid is needed as an arg
        # it can be extracted from the sysmeta for consistency
        cid = self._add_object(data)
        s_cid = self._set_sysmeta(pid, sysmeta)
        return s_cid

    def _add_object(self, data):
        """Add a data blob to the store"""
        # TODO: check that objects are not added if they already exist
        address = self.objects.put(data)
        return address.id

    def _set_sysmeta(self, pid, sysmeta):
        """Add a sysmeta document to the store"""
        cid = self.hash_string(pid)
        rel_path = self.rel_path(cid)
        full_path = Path(self.store_path) / "sysmeta" / rel_path
        parent = full_path.parent
        parent.mkdir(parents=True, exist_ok=True)
        with full_path.open(mode="wb") as file:
            file.write(cid.encode("utf-8"))
            formatId = " " + self.SYSMETA_NS
            file.write(formatId.encode("utf-8"))
            file.write(b"\x00")
            file.write(sysmeta)
        return cid

    def abs_path(self, cid):
        """Get the local path for a given content identifier (cid)"""
        address = self.objects.get(cid)
        if address == None:
            print("Not found in objects")
            address = self.sysmeta.get(cid)
        if address == None:
            print("Not found in sysmeta")
            return None
        else:
            return address.abspath

    def count(self):
        return self.objects.count()

    def hash_string(self, input):
        """Calculate the SHA-256 digest for a string, and return it in a base64 hex encoded string"""
        hex = hashlib.sha256(input.encode("utf-8")).hexdigest()
        return hex

    def rel_path(self, hash):
        """Return the storage path for a given hash hexdigest"""
        chunks = []
        for i in range(self.dir_depth):
            temp = hash[: self.dir_width]
            hash = hash[self.dir_width :]
            chunks.append(temp)
            if i == self.dir_depth - 1:
                chunks.append(hash)
        return "/".join(chunks)

