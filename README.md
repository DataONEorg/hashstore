## HashStore: hash-based object storage for DataONE data packages

- **Author**: Dou Mok, Matthew Brooke, Jing Tao, Matthew B. Jones
- **License**: [Apache 2](http://opensource.org/licenses/Apache-2.0)
- [Package source code on GitHub](https://github.com/DataONEorg/hashstore)
- [**Submit Bugs and feature requests**](https://github.com/DataONEorg/hashstore/issues)
- Contact us: support@dataone.org
- [DataONE discussions](https://github.com/DataONEorg/dataone/discussions)

HashStore is a server-side python package implementing a content-based identifier file system for storing and accessing data and metadata for DataONE services.  The package is used in DataONE system components that need direct, filesystem-based access to data objects, their system metadata, and extended metadata about the objects. This package is a core component of the [DataONE federation](https://dataone.org), and supports large-scale object storage for a variety of repositories, including the [KNB Data Repository](http://knb.ecoinformatics.org), the [NSF Arctic Data Center](https://arcticdata.io/catalog/), the [DataONE search service](https://search.dataone.org), and other repositories.

DataONE in general, and HashStore in particular, are open source, community projects.  We [welcome contributions](https://github.com/DataONEorg/hashstore/blob/main/CONTRIBUTING.md) in many forms, including code, graphics, documentation, bug reports, testing, etc.  Use the [DataONE discussions](https://github.com/DataONEorg/dataone/discussions) to discuss these contributions with us.


## Documentation

Documentation is a work in progress, and can be found on the [Metacat repository](https://github.com/NCEAS/metacat/blob/feature-1436-storage-and-indexing/docs/user/metacat/source/storage-subsystem.rst#physical-file-layout) as part of the storage redesign planning. Future updates will include documentation here as the package matures.

## HashStore Overview

HashStore is a content-addressable file management system that utilizes the content identifier of an object to address files. The system stores objects, references (refs) and metadata in its respective directories and provides an API for interacting with the store. HashStore storage classes (like `FileHashStore`) must implement the HashStore interface to ensure the expected usage of HashStore.

###### Public API Methods
- store_object
- verify_object
- tag_object
- find_object
- store_metadata
- retrieve_object
- retrieve_metadata
- delete_object
- delete_metadata
- get_hex_digest

For details, please see the HashStore interface (hashstore.py)


###### How do I create a HashStore?

To create or interact with a HashStore, instantiate a HashStore object with the following set of properties:
- store_path
- store_depth
- store_width
- store_algorithm
- store_metadata_namespace

```py
from hashstore import HashStoreFactory

# Instantiate a factory
hashstore_factory = HashStoreFactory()

# Create a properties dictionary with the required fields
properties = {
    "store_path": "/path/to/your/store",
    "store_depth": 3,
    "store_width": 2,
    "store_algorithm": "sha256",
    "store_metadata_namespace": "http://ns.dataone.org/service/types/v2.0",
}

# Get HashStore from factory
module_name = "hashstore.filehashstore.filehashstore"
class_name = "FileHashStore"
my_store = hashstore_factory.get_hashstore(module_name, class_name, properties)

# Store objects (.../[hashstore_path]/objects/)
pid = "j.tao.1700.1"
object = "/path/to/your/object.data"
object_metadata = my_store.store_object(pid, object)
object_cid = object_metadata.cid

# Store metadata (.../[hashstore_path]/metadata/)
# By default, storing metadata will use the given properties namespace `format_id`
pid = "j.tao.1700.1"
sysmeta = "/path/to/your/sysmeta/document.xml"
metadata_cid = my_store.store_metadata(pid, sysmeta)

# If you want to store other types of metadata, add an additional `format_id`.
pid = "j.tao.1700.1"
metadata = "/path/to/your/metadata/document.json"
format_id = "http://custom.metadata.com/json/type/v1.0"
metadata_cid = my_store.store_metadata(pid, metadata, format_id)

# ...
```

###### Working with objects (store, retrieve, delete)

In HashStore, objects are first saved as temporary files while their content identifiers are calculated. Once the default hash algorithm list and their hashes are generated, objects are stored in their permanent location using the store's algorithm's corresponding hash value, the store depth and the store width. Lastly, reference files are created for the object so that they can be found and retrieved given an identifier (ex. persistent identifier (pid)). Note: Objects are also stored once and only once.

By calling the various interface methods for  `store_object`, the calling app/client can validate, store and tag an object simultaneously if the relevant data is available. In the absence of an identifier (ex. persistent identifier (pid)), `store_object` can be called to solely store an object. The client is then expected to call `verify_object` when the relevant metadata is available to confirm that the object has been stored as expected. If the object is determined to be invalid (via `verify_object`), the client is expected to delete the object directly. Lastly, to finalize this process of storing an object (to make the object discoverable), the client calls `tag_object`. In summary, there are two expected paths to store an object:

```py
# All-in-one process which stores, validates and tags an object
objectMetadata objInfo = store_object(stream, pid, additional_algo, checksum, checksum_algo, objSize)

# Manual Process
# Store object
obj_metadata = store_object(stream)
# Validate object, throws exceptions if there is a mismatch and deletes the associated file
verify_object(obj_metadata, checksum, checksumAlgorithn, objSize)
# Tag object, makes the object discoverable (find, retrieve, delete)
tag_object(pid, cid)
```

**How do I retrieve an object if I have the pid?**
- To retrieve an object, call the Public API method `retrieve_object` which opens a stream to the object if it exists.

**How do I find an object or check that it exists if I have the pid?**
- To check if an object exists, call the Public API method `find_object` which will return the content identifier (cid) of the object if it exists.
- If desired, this cid can then be used to locate the object on disk by following HashStore's store configuration.

**How do I delete an object if I have the pid?**
- To delete an object and all its associated reference files, call the Public API method `delete_object` with `id_type` 'pid'.
- To delete only an object, call `delete_object` with `id_type` 'cid' which will remove the object if it is not referenced by any pids.
- Note, `delete_object` and `store_object` are synchronized based on a given 'pid'. An object that is in the process of being stored based on a pid should not be deleted at the same time. Additionally, `delete_object` further synchronizes with `tag_object` based on a `cid`. Every object is stored once, is unique and shares one cid reference file. The API calls to access this cid reference file must be coordinated to prevent file system locking exceptions.


###### Working with metadata (store, retrieve, delete)

HashStore's '/metadata' directory holds all metadata for objects stored in HashStore. To differentiate between metadata documents for a given object, HashStore includes the 'format_id' (format or namespace of the metadata) when generating the address of the metadata document to store (the hash of the 'pid' + 'format_id'). By default, calling `store_metadata` will use HashStore's default metadata namespace as the 'format_id' when storing metadata. Should the calling app wish to store multiple metadata files about an object, the client app is expected to provide a 'format_id' that represents an object format for the metadata type (ex. `store_metadata(stream, pid, format_id)`). 

**How do I retrieve a metadata file?**
- To find a metadata object, call the Public API method `retrieve_metadata` which returns a stream to the metadata file that's been stored with the default metadata namespace if it exists.
- If there are multiple metadata objects, a 'format_id' must be specified when calling `retrieve_metadata` (ex. `retrieve_metadata(pid, format_id)`)

**How do I delete a metadata file?**
- Like `retrieve_metadata`, call the Public API method `delete_metadata` to delete all metadata documents associated with the given pid.
- If there are multiple metadata objects, and you wish to only delete one type, a 'format_id' must be specified when calling `delete_metadata(pid, format_id)` to ensure the expected metadata object is deleted.


###### What are HashStore reference files?

HashStore assumes that every object to store has a respective identifier. This identifier is then used when storing, retrieving and deleting an object. In order to facilitate this process, we create two types of reference files:
- pid (persistent identifier) reference files 
- cid (content identifier) reference files

These reference files are implemented in HashStore underneath the hood with no expectation for modification from the calling app/client. The one and only exception to this process when the calling client/app does not have an identifier, and solely stores an objects raw bytes in HashStore (calling `store_object(stream)`).

**'pid' Reference Files**
- Pid (persistent identifier) reference files are created when storing an object with an identifier.
- Pid reference files are located in HashStores '/refs/pids' directory
- If an identifier is not available at the time of storing an object, the calling app/client must create this association between a pid and the object it represents by calling `tag_object` separately.
- Each pid reference file contains a string that represents the content identifier of the object it references
- Like how objects are stored once and only once, there is also only one pid reference file for each object.

**'cid' Reference Files**
- Cid (content identifier) reference files are created at the same time as pid reference files when storing an object with an identifier.
- Cid reference files are located in HashStore's '/refs/cids' directory
- A cid reference file is a list of all the pids that reference a cid, delimited by a new line ("\n") character


###### What does HashStore look like?

```shell
# Example layout in HashStore with three files stored along with its metadata and reference files.
# This uses a store depth of 3, with a width of 2 and "SHA-256" as its default store algorithm
## Notes:
## - Objects are stored using their content identifier as the file address
## - The reference file for each pid contains a single cid
## - The reference file for each cid contains multiple pids each on its own line

.../metacat/hashstore/
   ├── hashstore.yaml
   ├── objects
   |   ├── 4d
   |   │   └── 19
   |   │       └── 81
   |   |           └── 71eef969d553d4c9537b1811a7b078f9a3804fc978a761bc014c05972c
   |   ├── 94
   |   │   └── f9
   |   │       └── b6
   |   |           └── c88f1f458e410c30c351c6384ea42ac1b5ee1f8430d3e365e43b78a38a
   |   └── 44
   |       └── 73
   |           └── 51
   |               └── 6a592209cbcd3a7ba4edeebbdb374ee8e4a49d19896fafb8f278dc25fa
   └── metadata
   |   ├── 0d
   |   │   └── 55
   |   │       └── 55
   |   |           └── 5ed77052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e
   |   |               └── 323e0799524cec4c7e14d31289cefd884b563b5c052f154a066de5ec1e477da7
   |   |               └── sha256(pid+formatId_annotations)
   |   ├── a8
   |   │   └── 24
   |   │       └── 19
   |   |           └── 25740d5dcd719596639e780e0a090c9d55a5d0372b0eaf55ed711d4edf
   |   |               └── ddf07952ef28efc099d10d8b682480f7d2da60015f5d8873b6e1ea75b4baf689
   |   |               └── sha256(pid+formatId_annotations)
   |   └── 7f
   |       └── 5c
   |           └── c1
   |               └── 8f0b04e812a3b4c8f686ce34e6fec558804bf61e54b176742a7f6368d6
   |                   └── 9a2e08c666b728e6cbd04d247b9e556df3de5b2ca49f7c5a24868eb27cddbff2
   |                   └── sha256(pid+formatId_annotations)
   └── refs
       ├── cids
       |   ├── 4d
       |   |   └── 19
       |   |       └── 81
       |   |           └── 71eef969d553d4c9537b1811a7b078f9a3804fc978a761bc014c05972c
       |   ├── 94
       |   │   └── f9
       |   │       └── b6
       |   |           └── c88f1f458e410c30c351c6384ea42ac1b5ee1f8430d3e365e43b78a38a
       |   └── 44
       |       └── 73
       |           └── 51
       |               └── 6a592209cbcd3a7ba4edeebbdb374ee8e4a49d19896fafb8f278dc25fa
       └── pids
           ├── 0d
           |   └── 55
           |       └── 55
           |           └── 5ed77052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e
           ├── a8
           │   └── 24
           │       └── 19
           |           └── 25740d5dcd719596639e780e0a090c9d55a5d0372b0eaf55ed711d4edf
           └── 7f
               └── 5c
                   └── c1
                       └── 8f0b04e812a3b4c8f686ce34e6fec558804bf61e54b176742a7f6368d6
```

## Concurrency in HashStore

HashStore is both thread and process safe, and by default synchronizes calls to store & delete objects/metadata with Python's threading module. If you wish to use multiprocessing to parallelize your application, please declare a global environment variable `USE_MULTIPROCESSING` as `True` before initializing Hashstore. This will direct the relevant Public API calls to synchronize using the Python `multiprocessing` module's locks and conditions. Please see below for example:

```py
# Set the global environment variable
os.environ["USE_MULTIPROCESSING"] = "True"

# Check that the global environment variable has been set
use_multiprocessing = os.getenv("USE_MULTIPROCESSING", "False") == "True"
```


## Development build

HashStore is a python package, and built using the [Python Poetry](https://python-poetry.org) build tool.

To install `hashstore` locally, create a virtual environment for python 3.9+, 
install poetry, and then install or build the package with `poetry install` or `poetry build`, respectively.

To run tests, navigate to the root directory and run `pytest -s`. The test suite contains tests that
take a longer time to run (relating to the storage of large files) - to execute all tests, run
`pytest --run-slow`. To see detailed

## HashStore Client

Client API Options:
- `-getchecksum` (get_hex_digest)
- `-findobject`
- `-storeobject`
- `-storemetadata`
- `-retrieveobject`
- `-retrievemetadata`
- `-deleteobject`
- `-deletemetadata`

How to use HashStore client (command line app)
```sh
# Step 0: Install hashstore via poetry to create an executable script
$ poetry install

# Step 1: Create a HashStore
$ hashstore /path/to/store/ -chs -dp=3 -wp=2 -ap=SHA-256 -nsp="http://www.ns.test/v1"

# Get the checksum of a data object
$ hashstore /path/to/store/ -getchecksum -pid=persistent_identifier -algo=SHA-256

# Find an object (returns the content identifier)
$ hashstore /path/to/store/ -findobject -pid=persistent_identifier

# Store a data object
$ hashstore /path/to/store/ -storeobject -pid=persistent_identifier -path=/path/to/object

# Store a metadata object
$ hashstore /path/to/store/ -storemetadata -pid=persistent_identifier -path=/path/to/metadata/object -formatid=http://ns.dataone.org/service/types/v2.0

# Retrieve a data object
$ hashstore /path/to/store/ -retrieveobject -pid=persistent_identifier

# Retrieve a metadata object
$ hashstore /path/to/store/ -retrievemetadata -pid=persistent_identifier -formatid=http://ns.dataone.org/service/types/v2.0

# Delete a data object
$ hashstore /path/to/store/ -deleteobject -pid=persistent_identifier

# Delete a metadata file
$ hashstore /path/to/store/ -deletemetadata -pid=persistent_identifier -formatid=http://ns.dataone.org/service/types/v2.0
```

## License
```
Copyright [2022] [Regents of the University of California]

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## Acknowledgements
Work on this package was supported by:

- DataONE Network
- Arctic Data Center: NSF-PLR grant #2042102 to M. B. Jones, A. Budden, M. Schildhauer, and J. Dozier

Additional support was provided for collaboration by the National Center for Ecological Analysis and Synthesis, a Center funded by the University of California, Santa Barbara, and the State of California.

[![DataONE_footer](https://user-images.githubusercontent.com/6643222/162324180-b5cf0f5f-ae7a-4ca6-87c3-9733a2590634.png)](https://dataone.org)

[![nceas_footer](https://www.nceas.ucsb.edu/sites/default/files/2020-03/NCEAS-full%20logo-4C.png)](https://www.nceas.ucsb.edu)


