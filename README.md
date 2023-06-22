## HashStore: hash-based object storage for DataONE data packages

- **Author**: Matthew B. Jones, Dou Mok, Jing Tao, Matthew Brooke
- **License**: [Apache 2](http://opensource.org/licenses/Apache-2.0)
- [Package source code on GitHub](https://github.com/DataONEorg/hashstore)
- [**Submit Bugs and feature requests**](https://github.com/DataONEorg/hashstore/issues)
- Contact us: support@dataone.org
- [DataONE discussions](https://github.com/DataONEorg/dataone/discussions)

HashStore is a server-side python package implementing a content-based identifier file system for storing and accessing data and metadata for DataONE services.  The package is used in DataONE system components that need direct, filesystem-based access to data objects, their system metadata, and extended metadata about the objects. This package is a core component of the [DataONE federation](https://dataone.org), and supports large-scale object storage for a variety of repositories, including the [KNB Data Repository](http://knb.ecoinformatics.org), the [NSF Arctic Data Center](https://arcticdata.io/catalog/), the [DataONE search service](https://search.dataone.org), and other repositories.

DataONE in general, and HashStore in particular, are open source, community projects.  We [welcome contributions](https://github.com/DataONEorg/hashstore/blob/main/CONTRIBUTING.md) in many forms, including code, graphics, documentation, bug reports, testing, etc.  Use the [DataONE discussions](https://github.com/DataONEorg/dataone/discussions) to discuss these contributions with us.


## Documentation

Documentation is a work in progress, and can be found on the [Metacat repository](https://github.com/NCEAS/metacat/blob/feature-1436-storage-and-indexing/docs/user/metacat/source/storage-subsystem.rst#physical-file-layout) as part of the storage redesign planning. Future updates will include documentation here as the package matures.

## Development build

HashStore is a python package, and built using the [Python Poetry](https://python-poetry.org) build tool.

To install `hashstore` locally, create a virtual environment for python 3.9+, 
install poetry, and then install or build the package with `poetry install` or `poetry build`, respectively.

To run tests, navigate to the root directory and run `pytest -s`. The test suite contains tests that
take a longer time to run (relating to the storage of large files) - to execute all tests, run
`pytest --run-slow`. To see detailed

## Usage Example

To view more details about the Public API - see 'hashstore.py` interface documentation
```
# Instantiate a factory
hashstore_factory = HashStoreFactory()

# Create a properties dictionary with the required fields
hashstore_path = "/path/to/your/store"
properties = {
    "store_path": hashstore_path,
    "store_depth": 3,
    "store_width": 2,
    "store_algorithm": "sha256",
    "store_metadata_namespace": "http://ns.dataone.org/service/types/v2.0",
}

# Get HashStore from factory
module_name = "hashstore.filehashstore.filehashstore"
class_name = "FileHashStore"
my_store = factory.get_hashstore(module_name, class_name, properties)

# Store objects (.../[hashstore_path]/objects/)
pid = "j.tao.1700.1"
object = "/path/to/your/object.data"
hash_address = my_store.store_object(pid, object)
object_cid = hash_address.id

# Store metadata (.../[hashstore_path]/metadata/)
# By default, storing metadata will use the given properties namespace `format_id`
pid = "j.tao.1700.1"
sysmeta = "/path/to/your/sysmeta/document.xml"
metadata_cid = my_store.store_metadata(pid, sysmeta)
```

If you want to store other types of metadata, add an additional `format_id`.
```
pid = "j.tao.1700.1"
metadata = "/path/to/your/metadata/document.json"
format_id = "http://custom.metadata.com/json/type/v1.0"
metadata_cid = my_store.store_metadata(pid, metadata, format_id)
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
- Arctic Data Center: NSF-PLR grant #2042102 to M. B. Jones,  A. Budden, M. Schildhauer, and  J. Dozier

Additional support was provided for collaboration by the National Center for Ecological Analysis and Synthesis, a Center funded by the University of California, Santa Barbara, and the State of California.

[![DataONE_footer](https://user-images.githubusercontent.com/6643222/162324180-b5cf0f5f-ae7a-4ca6-87c3-9733a2590634.png)](https://dataone.org)

[![nceas_footer](https://www.nceas.ucsb.edu/sites/default/files/2020-03/NCEAS-full%20logo-4C.png)](https://www.nceas.ucsb.edu)


