# Core module for hashstore
from hashfs import HashFS
from io import StringIO

class D1Store:
    """Class representing the object store for DataONE"""
    fs = None

    def version(self):
        """Return the version number"""
        return("0.0.1")

    def init(self):
        """initialize the hashstore"""
        self.fs = HashFS('/tmp/mystore', depth=2, width=2, algorithm='sha256')
        #some_content = StringIO('Matt was here')
        #address = self.fs.put(some_content)
        return

    def add(self, data):
        """Add a data blob to the store"""
        address = self.fs.put(data)
        return(address.id)

    def path(self, cid):
        """Get the local path for a given content identifier (cid)"""
        address = self.fs.get(cid)
        return(address.abspath)