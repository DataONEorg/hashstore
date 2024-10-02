## HashStore: hash-based object storage for DataONE data packages

Version: 1.1.0
- DOI: [doi:10.18739/A2ZG6G87Q](https://doi.org/10.18739/A2ZG6G87Q)

## Contributors

- **Author**: Dou Mok, Matthew Brooke, Jing Tao, Jeanette Clarke, Ian Nesbitt, Matthew B. Jones
- **License**: [Apache 2](http://opensource.org/licenses/Apache-2.0)
- [Package source code on GitHub](https://github.com/DataONEorg/hashstore)
- [**Submit Bugs and feature requests**](https://github.com/DataONEorg/hashstore/issues)
- Contact us: support@dataone.org
- [DataONE discussions](https://github.com/DataONEorg/dataone/discussions)

## Citation

Cite this software as:

> Dou Mok, Matthew Brooke, Jing Tao, Jeanette Clarke, Ian Nesbitt, Matthew B. Jones. 2024. 
> HashStore: hash-based object storage for DataONE data packages. Arctic Data Center.
> [doi:10.18739/A2ZG6G87Q](https://doi.org/10.18739/A2ZG6G87Q)

## Introduction

HashStore is a server-side python package that implements a hash-based object storage file system 
for storing and accessing data and metadata for DataONE services. The package is used in DataONE 
system components that need direct, filesystem-based access to data objects, their system 
metadata, and extended metadata about the objects. This package is a core component of the 
[DataONE federation](https://dataone.org), and supports large-scale object storage for a variety 
of repositories, including the [KNB Data Repository](http://knb.ecoinformatics.org), the [NSF 
Arctic Data Center](https://arcticdata.io/catalog/), the [DataONE search service](https://search.dataone.org), and other repositories.

DataONE in general, and HashStore in particular, are open source, community projects.
We [welcome contributions](https://github.com/DataONEorg/hashstore/blob/main/CONTRIBUTING.md) in
many forms, including code, graphics, documentation, bug reports, testing, etc. Use
the [DataONE discussions](https://github.com/DataONEorg/dataone/discussions) to discuss these
contributions with us.

## Documentation

The documentation around HashStore's initial design phase can be found here in the [Metacat 
repository](https://github.com/NCEAS/metacat/blob/feature-1436-storage-and-indexing/docs/user/metacat/source/storage-subsystem.rst#physical-file-layout)
as part of the storage re-design planning. Future updates will include documentation here as the
package matures.

## HashStore Overview

HashStore is a hash-based object storage system that provides persistent file-based storage using 
content hashes to de-duplicate data. The system stores data objects, references (refs) and 
metadata in its respective directories and utilizes an identifier-based API for interacting 
with the store. HashStore storage classes (like `filehashstore`) must implement the HashStore 
interface to ensure the consistent and expected usage of HashStore.

### Public API Methods

- store_object
- tag_object
- store_metadata
- retrieve_object
- retrieve_metadata
- delete_object
- delete_if_invalid_object
- delete_metadata
- get_hex_digest

For details, please see the HashStore
interface [hashstore.py](https://github.com/DataONEorg/hashstore/blob/main/src/hashstore/hashstore.py)

### How do I create a HashStore?

To create or interact with a HashStore, instantiate a HashStore object with the following set of
properties:

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
    "store_algorithm": "SHA-256",
    "store_metadata_namespace": "https://ns.dataone.org/service/types/v2.0#SystemMetadata",
}

# Get HashStore from factory
module_name = "hashstore.filehashstore"
class_name = "FileHashStore"
hashstore = hashstore_factory.get_hashstore(module_name, class_name, properties)

# Store objects (.../[hashstore_path]/objects/)
pid = "j.tao.1700.1"
object_path = "/path/to/your/object.data"
object_metadata = hashstore.store_object(pid, object_path)
object_cid = object_metadata.cid

# Store metadata (.../[hashstore_path]/metadata/)
# By default, storing metadata will use the given properties namespace `format_id`
pid = "j.tao.1700.1"
sysmeta = "/path/to/your/sysmeta/document.xml"
metadata_cid = hashstore.store_metadata(pid, sysmeta)

# If you want to store other types of metadata, include a `format_id`.
pid = "j.tao.1700.1"
metadata = "/path/to/your/metadata/document.json"
format_id = "http://custom.metadata.com/json/type/v1.0"
metadata_cid_two = hashstore.store_metadata(pid, metadata, format_id)

# ...
```

### What does HashStore look like?

```sh
# Example layout in HashStore with a single file stored along with its metadata and reference files.
# This uses a store depth of 3 (number of nested levels/directories - e.g. '/4d/19/81/' within
# 'objects', see below), with a width of 2 (number of characters used in directory name - e.g. "4d",
# "19" etc.) and "SHA-256" as its default store algorithm
## Notes:
## - Objects are stored using their content identifier as the file address
## - The reference file for each pid contains a single cid
## - The reference file for each cid contains multiple pids each on its own line
## - There are two metadata docs under the metadata directory for the pid (sysmeta, annotations)

.../metacat/hashstore
├── hashstore.yaml
└── objects
|   └── 4d
|       └── 19
|           └── 81
|               └── 71eef969d553d4c9537b1811a7b078f9a3804fc978a761bc014c05972c
└── metadata
|   └── 0d
|       └── 55
|           └── 55
|               └── 5ed77052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e
|                   └── 323e0799524cec4c7e14d31289cefd884b563b5c052f154a066de5ec1e477da7
|                   └── sha256(pid+formatId_annotations)
└── refs
    ├── cids
    |   └── 4d
    |       └── 19
    |           └── 81
    |               └── 71eef969d553d4c9537b1811a7b078f9a3804fc978a761bc014c05972c
    └── pids
        └── 0d
            └── 55
                └── 55
                    └── 5ed77052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e
```

### Working with objects (store, retrieve, delete)

In HashStore, data objects begin as temporary files while their content identifiers are 
calculated. Once the default hash algorithm list and their hashes are generated, objects are stored
in their permanent locations using the hash value of the store's configured algorithm, and 
then divided accordingly based on the configured width and depth. Lastly, objects are 'tagged' 
with a given identifier (ex. persistent identifier (pid)). This process produces reference 
files, which allow objects to be found and retrieved with a given identifier.

- Note 1: An identifier can only be used once
- Note 2: Each object is stored once and only once using its content identifier (a checksum
  generated
  from using a hashing algorithm). Clients that attempt to store duplicate objects will receive
  the expected ObjectMetadata - with HashStore handling the de-duplication process under the hood.

By calling the various interface methods for  `store_object`, the calling app/client can validate,
store and tag an object simultaneously if the relevant data is available. In the absence of an
identifier (ex. persistent identifier (pid)), `store_object` can be called to solely store an
object. The client is then expected to call `delete_if_invalid_object` when the relevant 
metadata is available to confirm that the object is what is expected. And to finalize the data-only
storage process (to make the object discoverable), the client calls `tagObject``. In summary, there 
are two expected paths to store an object:

```py
import io
from hashstore import HashStoreFactory

# Instantiate a factory
hashstore_factory = HashStoreFactory()

# Create a properties dictionary with the required fields
properties = {
  "store_path": "/path/to/your/store",
  "store_depth": 3,
  "store_width": 2,
  "store_algorithm": "SHA-256",
  "store_metadata_namespace": "https://ns.dataone.org/service/types/v2.0#SystemMetadata",
}

# Get HashStore from factory
module_name = "hashstore.filehashstore"
class_name = "FileHashStore"
hashstore = hashstore_factory.get_hashstore(module_name, class_name, properties)

additional_algo = "sha224"
checksum = "sha3_224_checksum_value"
checksum_algo = "sha3_224"
obj_size = 123456
path = "/path/to/dou.test.1"
input_stream = io.open(path, "rb")
pid = "dou.test.1"
# All-in-one process which stores, validates and tags an object
obj_info_all_in_one = hashstore.store_object(input_stream, pid, additional_algo, checksum,
                                           checksum_algo, obj_size)

# Manual Process
# Store object
obj_info_manual = hashstore.store_object(input_stream)
# Validate object with expected values when available
hashstore.delete_if_invalid_object(obj_info_manual, checksum, checksum_algo, obj_size)
# Tag object, makes the object discoverable (find, retrieve, delete)
hashstore.tag_object(pid, obj_info_manual.cid)
```

**How do I retrieve an object if I have the pid?**

- To retrieve an object, call the Public API method `retrieve_object` which opens a stream to the
  object if it exists.

**How do I delete an object if I have the pid?**

- To delete an object and all its associated reference files, call the Public API
  method `delete_object`.
- Note, `delete_object` and `store_object` are synchronized processes based on a given `pid`.
  Additionally, `delete_object` further synchronizes with `tag_object` based on a `cid`. Every
  object is stored once, is unique and shares one cid reference file.

###### Working with metadata (store, retrieve, delete)

HashStore's '/metadata' directory holds all metadata for objects stored in HashStore. To
differentiate between metadata documents for a given object, HashStore includes the 'format_id' (
format or namespace of the metadata) when generating the address of the metadata document to store (
the hash of the 'pid' + 'format_id'). By default, calling `store_metadata` will use HashStore's
default metadata namespace as the 'format_id' when storing metadata. Should the calling app wish to
store multiple metadata files about an object, the client app is expected to provide a 'format_id'
that represents an object format for the metadata type (
ex. `store_metadata(stream, pid, format_id)`).

**How do I retrieve a metadata file?**

- To find a metadata object, call the Public API method `retrieve_metadata` which returns a stream
  to the metadata file that's been stored with the default metadata namespace if it exists.
- If there are multiple metadata objects, a 'format_id' must be specified when
  calling `retrieve_metadata` (ex. `retrieve_metadata(pid, format_id)`)

**How do I delete a metadata file?**

- Like `retrieve_metadata`, call the Public API method `delete_metadata` to delete all metadata
  documents associated with the given pid.
- If there are multiple metadata objects, and you wish to only delete one type, a 'format_id' must
  be specified when calling `delete_metadata(pid, format_id)` to ensure the expected metadata object
  is deleted.

### What are HashStore reference files?

HashStore assumes that every data object is referenced by its a respective identifier. This 
identifier is then used when storing, retrieving and deleting an object. In order to facilitate 
this process, we create two types of reference files:

- pid (persistent identifier) reference files
- cid (content identifier) reference files

These reference files are implemented in HashStore underneath the hood with no expectation for
modification from the calling app/client. The one and only exception to this process is when the
calling client/app does not have an identifier available (i.e. they receive the stream to store 
the data object first without any metadata, thus calling `store_object(stream)`).

**'pid' Reference Files**

- Pid (persistent identifier) reference files are created when storing an object with an identifier.
- Pid reference files are located in HashStores '/refs/pids' directory
- If an identifier is not available at the time of storing an object, the calling app/client must
  create this association between a pid and the object it represents by calling `tag_object`
  separately.
- Each pid reference file contains a single string that represents the content identifier of the 
  object it references
- Like how objects are stored once and only once, there is also only one pid reference file for each
  data object.

**'cid' Reference Files**

- Cid (content identifier) reference files are created at the same time as pid reference files when
  storing an object with an identifier.
- Cid reference files are located in HashStore's '/refs/cids' directory
- A cid reference file is a list of all the pids that reference a cid, delimited by a new line ("
  \n") character

## Concurrency in HashStore

HashStore is both threading and multiprocessing safe, and by default synchronizes calls to store & 
delete objects/metadata with Python's threading module. If you wish to use multiprocessing to 
parallelize your application, please declare a global environment variable `USE_MULTIPROCESSING` 
as `True` before initializing Hashstore. This will direct the relevant Public API calls to 
synchronize using the Python `multiprocessing` module's locks and conditions.
Please see below for example:

```py
import os

# Set the global environment variable
os.environ["USE_MULTIPROCESSING"] = "True"

# Check that the global environment variable has been set
use_multiprocessing = os.getenv("USE_MULTIPROCESSING", "False") == "True"
```

## Development build

HashStore is a python package, and built using the [Python Poetry](https://python-poetry.org)
build tool.

To install `hashstore` locally, create a virtual environment for python 3.9+,
install poetry, and then install or build the package with `poetry install` or `poetry build`,
respectively. Note, installing `hashstore` with poetry will also make the `hashstore` command 
available through the command line terminal (see `HashStore Client` section below for details).

To run tests, navigate to the root directory and run `pytest`. The test suite contains tests that
take a longer time to run (relating to the storage of large files) - to execute all tests, run
`pytest --run-slow`.

## HashStore Client

Client API Options:

- `-storeobject`
- `-storemetadata`
- `-retrieveobject`
- `-retrievemetadata`
- `-deleteobject`
- `-deletemetadata`
- `-getchecksum` (get_hex_digest)

How to use HashStore client (command line app)

```sh
# Step 0: Install hashstore via poetry to create an executable script
$ poetry install

# Step 1: Create a HashStore at your desired store path (ex. /var/metacat/hashstore)
$ hashstore /path/to/store/ -chs -dp=3 -wp=2 -ap=SHA-256 -nsp="http://www.ns.test/v1"

# Get the checksum of a data object
$ hashstore /path/to/store/ -getchecksum -pid=persistent_identifier -algo=SHA-256

# Store a data object
$ hashstore /path/to/store/ -storeobject -pid=persistent_identifier -path=/path/to/object

# Store a metadata object
$ hashstore /path/to/store/ -storemetadata -pid=persistent_identifier -path=/path/to/metadata/object -formatid=https://ns.dataone.org/service/types/v2.0#SystemMetadata

# Retrieve a data object
$ hashstore /path/to/store/ -retrieveobject -pid=persistent_identifier

# Retrieve a metadata object
$ hashstore /path/to/store/ -retrievemetadata -pid=persistent_identifier -formatid=https://ns.dataone.org/service/types/v2.0#SystemMetadata

# Delete a data object
$ hashstore /path/to/store/ -deleteobject -pid=persistent_identifier

# Delete a metadata file
$ hashstore /path/to/store/ -deletemetadata -pid=persistent_identifier -formatid=https://ns.dataone.org/service/types/v2.0#SystemMetadata
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
- Arctic Data Center: NSF-PLR grant #2042102 to M. B. Jones, A. Budden, M. Schildhauer, and J.
  Dozier

Additional support was provided for collaboration by the National Center for Ecological Analysis and
Synthesis, a Center funded by the University of California, Santa Barbara, and the State of
California.

[![DataONE_footer](https://user-images.githubusercontent.com/6643222/162324180-b5cf0f5f-ae7a-4ca6-87c3-9733a2590634.png)](https://dataone.org)

[![nceas_footer](https://www.nceas.ucsb.edu/sites/default/files/2020-03/NCEAS-full%20logo-4C.png)](https://www.nceas.ucsb.edu)


