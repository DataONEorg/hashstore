# hashtree

Describes storing directory trees in hashstore.

## Assumptions

- The root of a folder hierarchy is identified by a PID
- A folder hierarchy (including content) identified by a PID is immutable
- A mutation to a folder hierarchy results in a new folder hierarchy identified by a new PID
- Any subfolder may optionally be identified by a PID
- Any file contained within a folder hierarchy may be identified by a PID
- Permissions are associated with a PID and so apply to content of PID identified containers or files.
- A folder hierarchy may reference all or part of another identified folder hierarchy
- A folder is represented by a `container` in hashstore.

## Containers

Hashstore is augmented by adding an additional type of content that represents a `container`, the contents of which represent a single folder. A `container` has two types of entries: `file` that represents a single file and `folder` which represents a single subfolder. Each entry in a `container` has properties: `type`, `cid`, and `name`, where:

`type` - Indicates if the entry is a folder (`0`) or file (`1`).

`cid` - The content ID for the respective file or container.

`name` - The name component of the path to the entry. i.e. The last path segment for a subfolder or the file name (without path) for a file.

The CID for a container is computed from the serialized content on the container which includes the CID values for any subfolders. Hence, computing the CID for folders in a hierarchy requires a depth-first approach where the CIDs for leaves of a branch are computed before the branch.

A container is serialized space delimited rows in a text file. Each row represents an entry in the container, with values `type`, `cid`, and `name` in that order. Since folder or file names *may* contain whitespace, the `name` entry consumes the remainder of the row.

Since the CID for a container is dependent on its content, the content order is sorted by the `type` and `cid` values so hashing is consistent. Hence rows referencing subfolder containers will always appear before rows referencing files.

For example, given the folder hierarchy:

```
PID_1
├── A
│   ├── a1.txt
│   └── a2.txt
└── B
    └── b1.csv
```

The following `container` entries are created (`cid` values are truncated):

Container `ad5eb`:
```
1 10fbd a1.txt
1 c880c a2.txt
```

Container `cc08d`:
```
1 00e99 b1.csv
```

Container `dbc15`:
```
0 ad5eb A
0 cc08d B
```

The hashstore entry for `PID_1` might be:
```
$ cat refs/pids/53/b2/f2/58a2f3061a7bee4ba8b157aab217795c4692e2a2d8856e2fd97eb7fa3f
dbc1516e49e7437ea441f279570d32b1e2f149c44ab0a77682629215f4a5970b

$ cat refs/cids/db/c1/51/6e49e7437ea441f279570d32b1e2f149c44ab0a77682629215f4a5970b
PID_1
```

Each container is resolveable by the combination of PID and path. So for example,
the folder `B` within the context of `PID_1` can be resolved using the identifier `PID_1 B`. 
Similarly, the file `A/a2.txt` can be resolved with the identifier `PID_1 A/a2.txt`. 
Corresponding entries in hashstore `refs/pids` and `refs/cids` are created.

## Operations

### Get an object by path

Given a PID and a path, retrieve the corresponding object (file or folder) from hashstore.

Persistent identifiers for objects within a folder hierarchy are constructed by concatenating the PID with the path using a space as a delimiter. For example, to retrieve the object at path `data/file1.txt` within the folder hierarchy identified by PID `abc123`, the identifier would be `abc123 data/file1.txt`.

```
hashstore = HashStore(...)
path_pid = "<PID>" + " " + "<path>"
object_stream = hashstore.get_object(path_pid)
```

### Store a new folder hierarchy

To store a new folder hierarchy, recursively create `container` entries for each folder in the hierarchy, starting from the leaves and working up to the root. For each folder, create a `container` with entries for its subfolders and files, compute the CID for the container, and store it in hashstore. Finally, associate the root container's CID with the PID representing the entire folder hierarchy.

This is achieved by the `hash_store.store_folder()` method.

```
hashstore = HashStore(...)
pid = "<PID>"
source_path = "<local_folder_path>"
hashstore.store_folder(pid, source_path)
```

### Retrieve folder hierarchy structure

To retrieve the structure of a folder hierarchy identified by a PID, recursively resolve each `container` starting from the root PID. For each folder, read its `container` entries to identify subfolders and files, and continue resolving subfolders until the entire hierarchy is reconstructed.

This is achieved by the `hash_store.retrieve_folder()` method.

```
hashstore = HashStore(...)
pid = "<PID>"
destination_path = "<local_folder_path>"
hashstore.retrieve_folder(pid, destination_path)
```
