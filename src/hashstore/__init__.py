"""HashStore is a hash-based object store for data packages. It uses 
cryptographic hash functions to name files consistently.
HashStore creates a directory where objects and metadata are 
stored using a hash value as the name.

HashStore is mainly focused on storing DataONE data package contents
on a shared file system for simple and fast access by data management
processes that function across a cluster environment. Some properties:

- Data objects are immutable and never change
- Data objects are named using the SHA-256, base64-encoded hash of their contents
    (thus, a content-identifier)
- Metadata objects are stored with the formatId, a null character and its contents
- Metadata objects are named using the SHA-256 + formatId, base64-encoded hash of
    their persistent identifier (PID)
"""

from hashstore.hashstore import HashStore
from hashstore.hashaddress import HashAddress
from hashstore.hashstore_factory import HashStoreFactory

__all__ = ("HashStore", "HashAddress", "HashStoreFactory")
