# Core module for hashstore
from hashfs import HashFS
import hashlib
from io import StringIO


class ObjectStore:
    """Class representing the object store for Metacat"""

    # Class variables
    dir_depth = 3
    dir_width = 2

    def version(self):
        """Return the version number"""
        return "0.2.0"

    def __init__(self, store_path):
        """initialize the hashstore"""
        self.objects = HashFS(
            store_path + "/objects",
            depth=self.dir_depth,
            width=self.dir_width,
            algorithm="sha256",
        )
        self.sysmeta = HashFS(
            store_path + "/sysmeta",
            depth=self.dir_depth,
            width=self.dir_width,
            algorithm="sha256",
        )
        self.tags = HashFS(
            store_path + "/tags",
            depth=self.dir_depth,
            width=self.dir_width,
            algorithm="sha256",
        )
        return None

    def add_object(self, data):
        """Add a data blob to the store"""
        address = self.objects.put(data)
        return address.id

    def add_sysmeta(self, pid):
        """Add a sysmeta document to the store"""
        address = self.sysmeta.put(pid)
        return address.id

    def path(self, cid):
        """Get the local path for a given content identifier (cid)"""
        address = self.objects.get(cid)
        return address.abspath

    def count(self):
        return self.objects.count()

    def hash_string(self, input):
        """ "This function returns the SHA-256 hash of the input
        string passed into it"""

        hex = hashlib.sha256(input.encode("utf-8")).hexdigest()

        # return the hex representation of digest
        return hex

    def get_path(self, hash):
        """Return the storage path for a given hash hexdigest"""
        chunks = []
        for i in range(self.dir_depth):
            print(i)
            temp = hash[: self.dir_width]
            hash = hash[self.dir_width :]
            chunks.append(temp)
            if i == self.dir_depth - 1:
                chunks.append(hash)
        return "/".join(chunks)