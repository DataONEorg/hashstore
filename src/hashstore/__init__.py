"""HashStore is an object storage file system that provides persistent file-based
storage using content identifiers/hashes to de-duplicate data.

HashStore is mainly focused on storing DataONE data package contents
on a shared file system for simple and fast access by data management
processes that function across a cluster environment. Some properties:

- Data objects are immutable and never change
- Data objects are named using the base64-encoded hash of their contents
    (thus, a content-identifier)
- Metadata documents for a given identifier are stored in a directory structure
    based on the base64-encoded hash of the identifier
- Metadata objects are named using the base64-encoded hash of the given identifier
    + its respective format_id/namespace
- The relationships between data objects and metadata are managed with a reference
    system.
"""

from hashstore.hashstore import HashStore, HashStoreFactory

__all__ = ("HashStore", "HashStoreFactory")
__version__ = "1.1.0"
