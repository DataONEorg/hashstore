"""Implements a virtual hashstore.

A virtual hashstore is used for staging content that is to be added to a 
hashstore.

Staging associates PIDs with objects and folders, and computes their hashes. 
When changes are made, a difference can be computed and used to efficiently 
transmit changes to a hashtore.
"""
import collections.abc
import contextlib
import dataclasses
import hashlib
import io
import json
import os
import pathlib
import typing

import xattr_compat as xattrs

import hashstore.filehashstore
import hashstore.filehashstore_exceptions

ORG_DATAONE_CID = "org.dataone.hashstore.cid"
ORG_DATAONE_CID_ALGORITHM = "sha265"
FOLDER_ENTRY_FOLDER = 0
FOLDER_ENTRY_FILE = 1


def depth_first_walk(obj_path:pathlib.Path) -> collections.abc.Generator[pathlib.Path]:
    if obj_path.is_file():
        yield obj_path
        return
    if obj_path.is_dir():
        for item in obj_path.iterdir():
            if item.is_dir():
                yield from depth_first_walk(item)
            elif item.is_file():
                yield item
        yield obj_path


def compute_object_hash(obj_path: pathlib.Path, algorithm:str=ORG_DATAONE_CID_ALGORITHM) -> str:
    """Computes and returns the hash of the specified object path.
    
    This has the side effect of setting the ORG_DATAONE_CID xattr to a JSON
    struct that contains the current modification time, size, and hash value.
    
    The existing ORG_DATAONE_CID xattr is examined if present, and is returned 
    unless there is a mismatch of size or modification time.
    
    If obj_path is a folder, then the hash is computed as the hash of the list of
    type, cid, and name values. Since it is necessary to verify the consistency
    of the hashes for subfolders, a traversal to the leaves is necessary. Hence,
    this method can be expensive with deeply nested subfolders since even traversing
    """
    #Xattrs accepts os.PathLike
    attrs = xattrs.Xattrs(obj_path)
    obj_stat = obj_path.stat()
    if obj_path.is_file():
        try:
            # check for current existing cid value and return that if present
            entry = json.loads(attrs.get(ORG_DATAONE_CID, {}).decode("utf-8"))
            if entry["mtime"] == obj_stat.st_mtime and entry["size"] == obj_stat.st_size:
                # nothing has changed, so use the existing value
                return entry["cid"]
        except KeyError:
            # No or invalid xattr value, ignore and continue
            pass
        with obj_path.open('rb') as f:
            # Use the builtin chunker, requires python >= 3.11
            digest = hashlib.file_digest(f, algorithm)
        hexdigest = digest.hexdigest()
        # Set the xattr 
        entry = json.dumps({
            "cid": hexdigest,
            "mtime": obj_stat.st_mtime,
            "size": obj_stat.st_size
        }, ensure_ascii=False)
        attrs[ORG_DATAONE_CID] = entry.encode("utf-8")
    elif obj_path.is_dir():
        # Hash of a folder is the hash of the content. To check a folder, it
        # is necessary to traverse to the leaves to verify / compute the 
        # hashes. 
        pass
    else:
        raise ValueError(f"Path is not a file or folder.")
    return hexdigest
    

@dataclasses.dataclass
class FolderEntry:
    """A single entry in a Folder instance.
    
    An entry represents a file or folder record within a folder object.
    """
    kind: int # FOLDER_ENTRY_FOLDER | FOLDER_ENTRY_FILE
    cid: str  # The content id
    name: str # name of folder or file
    
    def get_cid(self, algorithm:str=ORG_DATAONE_CID_ALGORITHM) -> str:
        """Retrieves the contentId from the ORG_DATAONE_CID xattr or computes
        the CID if the xattr value is out of date.
        
        A CID value is computed if the file size or modified timestamp do
        not match the entries stored in the xattr structure or if the xattr
        is not set or otherwise cannot be read.
        """
        hasher = hashlib.new(self.algorithm)
        pass


@dataclasses.dataclass
class Folder:
    """An object that represents a single folder and its content.
    """
    name: str   # PID + "/" + path to the folder relative to root
    entries: list[FolderEntry] = dataclasses.field(default_factory=list)

    def __iter__(self):
        return self.entries.__iter__()

    def append(self, item: FolderEntry) -> None:
        self.entries.append(item)
        
    def compute_cid(self, algorithm:str=ORG_DATAONE_CID_ALGORITHM) -> str:
        """Computes the CID for this folder based on the content of the entries.
        
        The CID is computed as the hash of the list of type, cid, and name values.
        The entries are sorted by type and name to ensure a consistent hash value.
        """
        hasher = hashlib.new(algorithm)
        self.entries.sort(key=lambda x: (x.kind, x.name))
        for entry in self.entries:
            hasher.update(f"{entry.kind} {entry.cid} {entry.name}\n".encode("utf-8"))
        return hasher.hexdigest()
    
    @classmethod
    def deserialize(cls, stream: io.BytesIO, pid:str) -> "Folder":
        manifest = Folder(name=pid)
        with contextlib.closing(stream):
            header = stream.readline().decode("utf-8").strip()
            if not header.startswith("container "):
                msg = f"{pid} is not a container."
                raise ValueError(msg)
            for line in stream:
                line = line.decode("utf-8").strip()
                type_flag, cid, name = line.split(" ", 2)
                manifest.entries.append(FolderEntry(kind=int(type_flag), cid=cid, name=name))
        return manifest

    def serialize(
            self, 
        ) -> io.BytesIO:
        self.entries.sort(key=lambda x: (x.kind, x.name))
        dest_stream = io.BytesIO()
        dest_stream.name = "tmp"
        dest_stream.write(f"container {len(self.entries)}\n".encode("utf-8"))
        for entry in self.entries:
            dest_stream.write(f"{entry.kind} {entry.cid} {entry.name}\n".encode("utf-8"))
        dest_stream.seek(0)
        return dest_stream
        
    @property
    def size(self) -> int:
        return len(self.entries)
    

class VirtualHashStore(hashstore.filehashstore.FileHashStore):
    
    def __init__(self, properties):
        super().__init__(properties)
    
    def _find_object(self, pid: str) -> dict[str, str]:
        """Check if an object referenced by a pid exists and retrieve its content identifier.
        The `find_object` method validates the existence of an object based on the provided
        pid and returns the associated content identifier.

        :param str pid: Authority-based or persistent identifier of the object.

        :return: obj_info_dict:
            - cid: content identifier
            - cid_object_path: path to the object
            - cid_refs_path: path to the cid refs file
            - pid_refs_path: path to the pid refs file
            - sysmeta_path: path to the sysmeta file
        """
        self.fhs_logger.debug("Request to find object for for pid: %s", pid)
        self._check_string(pid, "pid")

        pid_ref_abs_path = self._get_hashstore_pid_refs_path(pid)
        if os.path.isfile(pid_ref_abs_path):
            # Read the file to get the cid from the pid reference
            pid_refs_cid = self._read_small_file_content(pid_ref_abs_path)

            # Confirm that the cid reference file exists
            cid_ref_abs_path = self._get_hashstore_cid_refs_path(pid_refs_cid)
            if os.path.isfile(cid_ref_abs_path):
                # Check that the pid is actually found in the cid reference file
                if self._is_string_in_refs_file(pid, cid_ref_abs_path):
                    # Object must also exist in order to return the cid retrieved
                    if self._exists("objects", pid_refs_cid):
                        cid_object_path =  self._get_hashstore_data_object_path(
                                pid_refs_cid
                            )
                    else:
                        cid_object_path = None
                    sysmeta_doc_name = self._computehash(pid + self.sysmeta_ns)
                    metadata_directory = self._computehash(pid)
                    metadata_rel_path = pathlib.Path(*self._shard(metadata_directory))
                    sysmeta_full_path = (
                        self._get_store_path("metadata")
                        / metadata_rel_path
                        / sysmeta_doc_name
                    )
                    obj_info_dict = {
                        "cid": pid_refs_cid,
                        "cid_object_path": cid_object_path,
                        "cid_refs_path": cid_ref_abs_path,
                        "pid_refs_path": pid_ref_abs_path,
                        "sysmeta_path": (
                            sysmeta_full_path
                            if os.path.isfile(sysmeta_full_path)
                            else "Does not exist."
                        ),
                    }
                    return obj_info_dict
                else:
                    # If not, it is an orphan pid refs file
                    err_msg = (
                        f"Pid reference file exists with cid: {pid_refs_cid} for pid: {pid} but "
                        f"is missing from cid refs file: {cid_ref_abs_path}"
                    )
                    self.fhs_logger.error(err_msg)
                    raise hashstore.filehashstore_exceptions.PidNotFoundInCidRefsFile(err_msg)
            else:
                err_msg = (
                    f"Pid reference file exists with cid: {pid_refs_cid} but cid reference file "
                    + f"not found: {cid_ref_abs_path} for pid: {pid}"
                )
                self.fhs_logger.error(err_msg)
                raise hashstore.filehashstore_exceptions.OrphanPidRefsFileFound(err_msg)
        else:
            err_msg = (
                f"Pid reference file not found for pid ({pid}): {pid_ref_abs_path}"
            )
            self.fhs_logger.error(err_msg)
            raise hashstore.filehashstore_exceptions.PidRefsDoesNotExist(err_msg)
    
    
    def commit_folder(
        self,
        pid: str,
        root_path: typing.Union[str, pathlib.Path],
        child_path: typing.Optional[typing.Union[str, pathlib.Path]] = None,
        additional_algorithm: typing.Optional[str] = None,
        checksum: typing.Optional[str] = None,
        checksum_algorithm: typing.Optional[str] = None,
        expected_object_size: typing.Optional[int] = None,
        pattern: typing.Optional[str] = None,
    ) -> typing.Optional[hashstore.filehashstore.ObjectMetadata]:
        """Store a folder (and subfolders) as container objects.

        Traverses the folder hierarchy in a depth first manner so that
        the leaf elements are computed for inclusion in parent hashes.

        Args:
            pid (str): The context within which this folder is being stored
            root_path (str): Path to the root of the folder.
            child_path (str): Path to folder being stored relative to the root_path. If None, assumes root_path.
            
        Returns:
            str: CID for the container
        """
        # Get the relative path for the object / folder
        root_path = pathlib.Path(root_path)
        if child_path is None:
            child_path = root_path
        else:
            child_path = pathlib.Path(child_path)
        relative_path = child_path.relative_to(root_path)
        path_pid = pid
        container_name = "root"
        if str(relative_path) != ".":
            path_pid = f"{pid}/{relative_path}"
            container_name = str(relative_path)

        # Check if this container already exists
        try:
            # resolve pid, path to CID. This raises if not found
            _entry = self._find_object(path_pid)
            size = os.path.getsize(
                self._build_hashstore_data_object_path(_entry["cid"])
            )
            return hashstore.filehashstore.ObjectMetadata(
                pid=path_pid, cid=_entry["cid"], obj_size=size, hex_digests={}
            )
        except hashstore.filehashstore.PidNotFoundInCidRefsFile:
            pass
        except hashstore.filehashstore.PidRefsDoesNotExist:
            pass

        # Container doesn't exist
        manifest = Folder(name=path_pid)
        for item in child_path.iterdir():
            if item.is_dir():
                meta = self.commit_folder(
                    pid,
                    root_path,
                    child_path=item.absolute(),
                    additional_algorithm=additional_algorithm,
                    checksum=checksum,
                    checksum_algorithm=checksum_algorithm,
                    expected_object_size=expected_object_size,
                    pattern=pattern,
                )
                if meta is not None:
                    manifest.append(FolderEntry(kind=0, cid=meta.cid, name=item.name))
            elif pattern is None and item.is_file():
                # If no pattern then grab all files, otherwise defer to 
                # globbing match later.
                item_pid = f"{pid}/{item.relative_to(root_path)}"
                self.fhs_logger.debug("store_folder {item_pid=}")
                with item.open("r") as item_stream:
                    _cid = self._computehash(item_stream)
                self._store_hashstore_refs_files(item_pid, _cid)
                manifest.append(FolderEntry(kind=1, cid=_cid, name=item.name))
        if pattern is not None:
            # globbing pattern was specified. Grab the matching files here.
            for item in child_path.glob(pattern):
                if item.is_file():
                    item_pid = f"{pid}/{item.relative_to(root_path)}"
                    with item.open("r") as item_stream:
                        _cid = self._computehash(item_stream)
                    self._store_hashstore_refs_files(item_pid, _cid)
                    manifest.append(FolderEntry(kind=1, cid=_cid, name=item.name))
        if manifest.size == 0:
            return None
        
        return self.store_object(
            path_pid,
            data=manifest.serialize(),
            additional_algorithm=additional_algorithm,
            checksum=checksum,
            checksum_algorithm=checksum_algorithm,
            expected_object_size=None,
        )

        
    def folder_content(self, pid:str, depth:int=0, depth_first:bool=True) -> typing.Generator:
        """Yield the content of a folder, breadth first, recursively.
            (depth, type, CID, name)
        """
        # Retrieve the container object
        with contextlib.closing(self.retrieve_object(pid)) as obj_stream:
            manifest = Folder.deserialize(obj_stream, pid)
        if depth_first:
            for entry in manifest:
                if entry.kind == 0:
                    yield (depth, entry.kind, entry.cid, f"{pid}/{entry.name}")
                    yield from self.folder_content(f"{pid}/{entry.name}", depth=depth+1, depth_first=depth_first)
                else:
                    yield (depth, entry.kind, entry.cid, f"{pid}/{entry.name}")
        else:
            for entry in manifest:
                yield (depth, entry.kind, entry.cid, f"{pid}/{entry.name}")
            for entry in manifest:
                if entry.kind == 0:
                    # folder, recurse
                    yield from self.folder_content(f"{pid}/{entry.name}", depth=depth+1, depth_first=depth_first)
                    
    def get_object_status(self, pid: str) -> dict:
        self.fhs_logger.debug("Request to get object status for pid: %s", pid)
        self._check_string(pid, "pid")

        object_status_dict = {}
        try:
            object_info_dict = self._find_object(pid)
            object_cid = object_info_dict.get("cid")
            if object_cid:
                try:
                    obj_path = self._get_hashstore_data_object_path(object_cid)
                    object_status_dict["size"] = os.path.getsize(obj_path)
                    object_status_dict["modtime"] = os.path.getmtime(obj_path)
                    object_status_dict["accesstime"] = os.path.getatime(obj_path)
                except FileNotFoundError as e:
                    msg = f"No object found for CID {object_cid}"
                    self.fhs_logger.warning(msg)
                    object_status_dict["size"] = 0
                    object_status_dict["modtime"] = "-"
                    object_status_dict["accesstime"] = "-"
            else:
                err_msg = f"No object found for pid: {pid}"
                self.fhs_logger.warning(err_msg)
                raise KeyError(err_msg)
        except KeyError as ke:
            err_msg = f"No object found for pid: {pid}. Details: {ke}"
            self.fhs_logger.warning(err_msg)
            raise KeyError(err_msg)

        return object_status_dict

