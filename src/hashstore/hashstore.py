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
        s_cid = self._set_sysmeta(pid, sysmeta, cid)
        return s_cid

    def store_object(self, data):
        """Add a data object to the store"""
        cid = self._add_object(data)
        return cid

    def store_sysmeta(self, pid, sysmeta, cid):
        """Add a metadata object to the store"""
        s_cid = self._set_sysmeta(pid, sysmeta, cid)
        return s_cid

    def retrieve_sysmeta(self, pid):
        """Returns the sysmeta of a given persistent identifier (pid)"""
        sysmeta = self._get_sysmeta(pid)[1]
        return sysmeta

    def retrieve(self, pid):
        """Returns the sysmeta and a buffered stream of a cid obj given a persistent identifier (pid)"""
        sys_content = self._get_sysmeta(pid)
        cid = sys_content[0][:64]
        sysmeta = sys_content[1]
        c_stream = self.objects.open(cid)
        return sysmeta, c_stream

    def _add_object(self, data):
        """Add a data blob to the store"""
        address = self.objects.put(data)
        return address.id

    def _set_sysmeta(self, pid, sysmeta, obj_cid):
        """Add a sysmeta document to the store"""
        s_cid = self._hash_string(pid)
        rel_path = self._rel_path(s_cid)
        full_path = Path(self.store_path) / "sysmeta" / rel_path
        parent = full_path.parent
        parent.mkdir(parents=True, exist_ok=True)
        with full_path.open(mode="wb") as file:
            file.write(obj_cid.encode("utf-8"))
            formatId = " " + self.SYSMETA_NS
            file.write(formatId.encode("utf-8"))
            file.write(b"\x00")
            file.write(sysmeta)
        return s_cid

    def _get_sysmeta(self, pid):
        """Returns a list containing the sysmeta header and content given a persistent identifier (pid)"""
        s_cid = self._hash_string(pid)
        s_path = self.sysmeta.open(s_cid)
        s_content = s_path.read().decode("utf-8").split("\x00", 1)
        s_path.close()
        return s_content

    def _hash_string(self, input):
        """Calculate the SHA-256 digest for a string, and return it in a base64 hex encoded string"""
        hex = hashlib.sha256(input.encode("utf-8")).hexdigest()
        return hex

    def _abs_path(self, cid):
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

    def _rel_path(self, hash):
        """Return the storage path for a given hash hexdigest"""
        chunks = []
        for i in range(self.dir_depth):
            temp = hash[: self.dir_width]
            hash = hash[self.dir_width :]
            chunks.append(temp)
            if i == self.dir_depth - 1:
                chunks.append(hash)
        return "/".join(chunks)

    def _count(self):
        return self.objects.count()
