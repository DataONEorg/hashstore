"""Core module for FileHashStore"""
import io
import shutil
import threading
import time
import hashlib
import os
from pathlib import Path
from contextlib import closing
from tempfile import NamedTemporaryFile
from hashstore import HashStore
from hashstore.hashaddress import HashAddress
from hashstore.filehashstore.filehashstore_config import (
    STORE_PATH,
    ALGORITHM,
    DIR_DEPTH,
    DIR_WIDTH,
    SYSMETA_NS,
    DEFAULT_ALGO_LIST,
    OTHER_ALGO_LIST,
)


class FileHashStore(HashStore):
    """FileHashStore is a content addressable file manager based on Derrick
    Gilland's 'hashfs' library. It supports the storage of objects on disk using
    an authority-based identifier's hex digest with a given hash algorithm value
    to address files.

    Args:
        root (str): Directory path used as root of storage space. Defaults to
        "/var/filehashstore/" if no path supplied.
    """

    def __init__(self, root=None, properties=None):
        if root is None:
            self.root = os.path.realpath(STORE_PATH)
        else:
            self.root = os.path.realpath(root)
        self.objects = self.root + "/objects"
        self.sysmeta = self.root + "/sysmeta"
        self.sysmeta_ns = SYSMETA_NS
        self.depth = DIR_DEPTH
        self.width = DIR_WIDTH
        self.algorithm = ALGORITHM
        self.default_algo_list = DEFAULT_ALGO_LIST
        self.other_algo_list = OTHER_ALGO_LIST
        self.fmode = 0o664
        self.dmode = 0o755
        self.time_out_sec = 1
        self.object_lock = threading.Lock()
        self.sysmeta_lock = threading.Lock()
        self.object_locked_pids = []
        self.sysmeta_locked_pids = []

    # Public API / HashStore Interface Methods

    def store_object(
        self,
        pid,
        data,
        additional_algorithm="sha256",
        checksum=None,
        checksum_algorithm=None,
    ):
        # Validate input parameters
        if pid is None or pid.replace(" ", "") == "":
            raise ValueError(f"Pid cannot be None or empty, pid: {pid}")
        if (
            not isinstance(data, str)
            and not isinstance(data, Path)
            and not isinstance(data, io.BufferedIOBase)
        ):
            raise TypeError(
                f"Data must be a path, string or buffered stream, data type supplied: {type(data)}"
            )
        if isinstance(data, str):
            if data.replace(" ", "") == "":
                raise TypeError("Data string cannot be empty")
        # Format additional algorithm if supplied
        additional_algorithm_checked = None
        if additional_algorithm != self.algorithm and additional_algorithm is not None:
            additional_algorithm_checked = self.clean_algorithm(additional_algorithm)
        # Checksum and checksum_algorithm must both be supplied
        if checksum is not None:
            if checksum_algorithm is None or checksum_algorithm.replace(" ", "") == "":
                raise ValueError(
                    "checksum_algorithm cannot be None or empty if checksum is supplied."
                )
        checksum_algorithm_checked = None
        if checksum_algorithm is not None:
            checksum_algorithm_checked = self.clean_algorithm(checksum_algorithm)
            if checksum is None or checksum.replace(" ", "") == "":
                raise ValueError(
                    "checksum cannot be None or empty if checksum_algorithm is supplied."
                )

        # Wait for the pid to release if it's in use
        while pid in self.object_locked_pids:
            time.sleep(self.time_out_sec)
        # Modify object_locked_pids consecutively
        with self.object_lock:
            self.object_locked_pids.append(pid)
        try:
            hash_address = self.put_object(
                pid,
                data,
                additional_algorithm=additional_algorithm_checked,
                checksum=checksum,
                checksum_algorithm=checksum_algorithm_checked,
            )
        finally:
            # Release pid
            with self.object_lock:
                self.object_locked_pids.remove(pid)
        return hash_address

    def store_sysmeta(self, pid, sysmeta):
        # Validate input parameters
        if pid is None or pid.replace(" ", "") == "":
            raise ValueError(f"Pid cannot be None or empty, pid: {pid}")
        if (
            not isinstance(sysmeta, str)
            and not isinstance(sysmeta, Path)
            and not isinstance(sysmeta, io.BufferedIOBase)
        ):
            raise TypeError(
                f"Sysmeta must be a path or string object, data type supplied: {type(sysmeta)}"
            )
        if isinstance(sysmeta, str):
            if sysmeta.replace(" ", "") == "":
                raise TypeError("Data string cannot be empty")

        # Wait for the pid to release if it's in use
        while pid in self.sysmeta_locked_pids:
            time.sleep(self.time_out_sec)
        # Modify sysmeta_locked_pids consecutively
        with self.sysmeta_lock:
            self.sysmeta_locked_pids.append(pid)
        try:
            sysmeta_cid = self.put_sysmeta(pid, sysmeta)
        finally:
            # Release pid
            with self.sysmeta_lock:
                self.sysmeta_locked_pids.remove(pid)
        return sysmeta_cid

    def retrieve_object(self, pid):
        if pid is None or pid.replace(" ", "") == "":
            raise ValueError(f"Pid cannot be None or empty, pid: {pid}")

        entity = "objects"
        ab_id = self.get_sha256_hex_digest(pid)
        sysmeta_exists = self.exists(entity, ab_id)
        if sysmeta_exists:
            obj_stream = self.open(entity, ab_id)
        else:
            raise ValueError(f"No sysmeta found for pid: {pid}")
        return obj_stream

    def retrieve_sysmeta(self, pid):
        if pid is None or pid.replace(" ", "") == "":
            raise ValueError(f"Pid cannot be None or empty, pid: {pid}")

        entity = "sysmeta"
        ab_id = self.get_sha256_hex_digest(pid)
        sysmeta_exists = self.exists(entity, ab_id)
        if sysmeta_exists:
            ab_id = self.get_sha256_hex_digest(pid)
            s_path = self.open(entity, ab_id)
            s_content = s_path.read().decode("utf-8").split("\x00", 1)
            s_path.close()
            sysmeta = s_content[1]
        else:
            raise ValueError(f"No sysmeta found for pid: {pid}")
        return sysmeta

    def delete_object(self, pid):
        if pid is None or pid.replace(" ", "") == "":
            raise ValueError(f"Pid cannot be None or empty, pid: {pid}")

        entity = "objects"
        ab_id = self.get_sha256_hex_digest(pid)
        self.delete(entity, ab_id)
        return True

    def delete_sysmeta(self, pid):
        if pid is None or pid.replace(" ", "") == "":
            raise ValueError(f"Pid cannot be None or empty, pid: {pid}")

        entity = "sysmeta"
        ab_id = self.get_sha256_hex_digest(pid)
        self.delete(entity, ab_id)
        return True

    def get_hex_digest(self, pid, algorithm):
        if pid is None or pid.replace(" ", "") == "":
            raise ValueError(f"Pid cannot be None or empty, pid: {pid}")
        if algorithm is None or algorithm.replace(" ", "") == "":
            raise ValueError(f"Algorithm cannot be None or empty, pid: {pid}")

        entity = "objects"
        algorithm = self.clean_algorithm(algorithm)
        ab_id = self.get_sha256_hex_digest(pid)
        if not self.exists(entity, ab_id):
            raise ValueError(f"No object found for pid: {pid}")
        c_stream = self.open(entity, ab_id)
        hex_digest = self.computehash(c_stream, algorithm=algorithm)
        return hex_digest

    # FileHashStore Core Methods

    def put_object(
        self,
        pid,
        file,
        extension=None,
        additional_algorithm=None,
        checksum=None,
        checksum_algorithm=None,
    ):
        """Store contents of `file` on disk using the hash of the given pid

        Args:
            pid (string): Authority-based identifier. \n
            file (mixed): Readable object or path to file. \n
            extension (str, optional): Optional extension to append to file
                when saving. \n
            additional_algorithm (str, optional): Optional algorithm value to include
                when returning hex digests. \n
            checksum (str, optional): Optional checksum to validate object
                against hex digest before moving to permanent location. \n
            checksum_algorithm (str, optional): Algorithm value of given checksum.

        Returns:
            hash_address (HashAddress): object that contains the permanent address,
            relative file path, absolute file path, duplicate file boolean and hex
            digest dictionary.
        """
        stream = Stream(file)

        with closing(stream):
            (
                ab_id,
                rel_path,
                abs_path,
                is_duplicate,
                hex_digest_dict,
            ) = self._move_and_get_checksums(
                pid,
                stream,
                extension,
                additional_algorithm,
                checksum,
                checksum_algorithm,
            )

        hash_address = HashAddress(
            ab_id, rel_path, abs_path, is_duplicate, hex_digest_dict
        )
        return hash_address

    def _move_and_get_checksums(
        self,
        pid,
        stream,
        extension=None,
        additional_algorithm=None,
        checksum=None,
        checksum_algorithm=None,
    ):
        """Copy the contents of `stream` onto disk with an optional file
        extension appended. The copy process uses a temporary file to store the
        initial contents and returns a dictionary of algorithms and their
        hex digest values. If the file already exists, the method will immediately
        return with is_duplicate: True and "None" for the remaining HashAddress
        attributes. If an algorithm and checksum is provided, it will proceed to
        validate the object (and delete the tmpFile if the hex digest stored does
        not match what is provided).

        Args:
            pid (string): authority-based identifier. \n
            stream (io.BufferedReader): object stream. \n
            extension (str, optional): Optional extension to append to file
                when saving. \n
            additional_algorithm (str, optional): Optional algorithm value to include
                when returning hex digests. \n
            checksum (str, optional): Optional checksum to validate object
                against hex digest before moving to permanent location. \n
            checksum_algorithm (str, optional): Algorithm value of given checksum. \n

        Returns:
            hash_address (HashAddress): object that contains the permanent address,
            relative file path, absolute file path, duplicate file boolean and hex
            digest dictionary.
        """
        entity = "objects"
        ab_id = self.get_sha256_hex_digest(pid)
        abs_file_path = self.build_abs_path(entity, ab_id, extension)
        self.create_path(os.path.dirname(abs_file_path))
        # Only put file if it doesn't exist
        if os.path.isfile(abs_file_path):
            raise FileExistsError(
                f"File already exists for pid: {pid} at {abs_file_path}"
            )
        else:
            rel_file_path = os.path.relpath(abs_file_path, self.objects)

        # Create temporary file and calculate hex digests
        hex_digests, tmp_file_name = self._mktempfile(stream, additional_algorithm)

        # Only move file if it doesn't exist.
        # Files are stored once and only once
        if not os.path.isfile(abs_file_path):
            if checksum_algorithm is not None and checksum is not None:
                hex_digest_stored = hex_digests[checksum_algorithm]
                if hex_digest_stored != checksum:
                    self.delete(entity, tmp_file_name)
                    raise ValueError(
                        "Hex digest and checksum do not match - file not stored. "
                        f"Algorithm: {checksum_algorithm}. "
                        f"Checksum provided: {checksum} != Hex Digest: {hex_digest_stored}"
                    )
            is_duplicate = False
            try:
                shutil.move(tmp_file_name, abs_file_path)
            except Exception as err:
                # Revert storage process for the time being for any failure
                # TODO: Discuss handling of permissions, memory and storage exceptions
                print(f"Unexpected {err=}, {type(err)=}")
                if os.path.isfile(abs_file_path):
                    self.delete(entity, abs_file_path)
                self.delete(entity, tmp_file_name)
                # TODO: Log exception
                # f"Aborting Upload - an unexpected error has occurred when moving file: {ab_id} - Error: {err}"
                raise
        else:
            # Else delete temporary file
            is_duplicate = True
            self.delete(entity, tmp_file_name)

        return ab_id, rel_file_path, abs_file_path, is_duplicate, hex_digests

    def _mktempfile(self, stream, algorithm=None):
        """Create a named temporary file from a `Stream` object and
        return its filename and a dictionary of its algorithms and hex digests.
        If an algorithm is provided, it will add the respective hex digest to
        the dictionary.

        Args:
            stream (io.BufferedReader): Object stream.
            algorithm (string): Algorithm of additional hex digest to generate.

        Returns:
            hex_digest_dict, tmp.name (tuple pack):
                hex_digest_dict (dictionary): Algorithms and their hex digests.
                tmp.name: Name of temporary file created and written into.
        """

        # Create temporary file in .../{store_path}/tmp
        tmp_root_path = self.get_store_path("objects") / "tmp"
        # Physically create directory if it doesn't exist
        if os.path.exists(tmp_root_path) is False:
            self.create_path(tmp_root_path)
        tmp = NamedTemporaryFile(dir=tmp_root_path, delete=False)

        # Ensure tmp file is created with desired permissions
        if self.fmode is not None:
            oldmask = os.umask(0)
            try:
                os.chmod(tmp.name, self.fmode)
            finally:
                os.umask(oldmask)

        # Additional hash object to digest
        if algorithm is not None:
            if algorithm in self.other_algo_list:
                self.default_algo_list.append(algorithm)
            elif algorithm not in self.default_algo_list:
                raise ValueError(f"Algorithm not supported: {algorithm}")

        hash_algorithms = [
            hashlib.new(algorithm) for algorithm in self.default_algo_list
        ]

        # tmp is a file-like object that is already opened for writing by default
        with tmp as tmp_file:
            for data in stream:
                tmp_file.write(self._to_bytes(data))
                for hash_algorithm in hash_algorithms:
                    hash_algorithm.update(self._to_bytes(data))

        hex_digest_list = [
            hash_algorithm.hexdigest() for hash_algorithm in hash_algorithms
        ]
        hex_digest_dict = dict(zip(self.default_algo_list, hex_digest_list))

        return hex_digest_dict, tmp.name

    def put_sysmeta(self, pid, sysmeta):
        """Store contents of `sysmeta` on disk using the hash of the given pid

        Args:
            pid (string): Authority-based identifier.
            sysmeta (mixed): String or path to sysmeta document.

        Returns:
            ab_id (string): Address of the sysmeta document.
        """

        # Create tmp file and write to it
        sysmeta_stream = Stream(sysmeta)
        with closing(sysmeta_stream):
            sysmeta_tmp = self._mktmpsysmeta(sysmeta_stream, self.sysmeta_ns)

        # Target path (permanent location)
        ab_id = self.get_sha256_hex_digest(pid)
        rel_path = "/".join(self.shard(ab_id))
        full_path = self.get_store_path("sysmeta") / rel_path

        # Move sysmeta to target path
        if os.path.exists(sysmeta_tmp):
            try:
                parent = full_path.parent
                parent.mkdir(parents=True, exist_ok=True)
                # Sysmeta will be replaced if it exists
                shutil.move(sysmeta_tmp, full_path)
                return ab_id
            except Exception as err:
                # TODO: Discuss specific error handling
                # isADirectoryError/notADirectoryError - if src/dst are directories, cannot move
                # OSError - if dst is a non-empty directory and insufficient permissions
                # TODO: Log error - err
                # Delete tmp file if it exists
                if os.path.exists(sysmeta_tmp):
                    self.sysmeta.delete(sysmeta_tmp)
                print(f"Unexpected {err=}, {type(err)=}")
                raise
        else:
            raise FileNotFoundError(
                f"sysmeta_tmp file not found: {sysmeta_tmp}. Unable to move sysmeta `{ab_id}` for pid `{pid}`"
            )

    def _mktmpsysmeta(self, stream, namespace):
        """Create a named temporary file with `sysmeta` bytes and `namespace`.

        Args:
            stream (io.BufferedReader): Sysmeta stream.
            namespace (string): Format of sysmeta.

        Returns:
            tmp.name (string): Name of temporary file created and written into.
        """
        # Create temporary file in .../{store_path}/tmp
        tmp_root_path = self.get_store_path("sysmeta") / "tmp"
        # Physically create directory if it doesn't exist
        if os.path.exists(tmp_root_path) is False:
            self.create_path(tmp_root_path)

        tmp = NamedTemporaryFile(dir=tmp_root_path, delete=False)
        # Ensure tmp file is created with desired permissions
        if self.fmode is not None:
            oldmask = os.umask(0)
            try:
                os.chmod(tmp.name, self.fmode)
            finally:
                os.umask(oldmask)

        # tmp is a file-like object that is already opened for writing by default
        with tmp as tmp_file:
            tmp_file.write(namespace.encode("utf-8"))
            tmp_file.write(b"\x00")
            for data in stream:
                tmp_file.write(self._to_bytes(data))

        return tmp.name

    # FileHashStore Utility & Supporting Methods

    def clean_algorithm(self, algorithm_string):
        """Format a string and ensure that it is supported and compatible with
        the python hashlib library.

        Args:
            algorithm_string (string): Algorithm to validate.

        Returns:
            cleaned_string (string): `hashlib` supported algorithm string.
        """
        count = 0
        for char in algorithm_string:
            if char.isdigit():
                count += 1
        if count > 3:
            cleaned_string = algorithm_string.lower().replace("-", "_")
        else:
            cleaned_string = algorithm_string.lower().replace("-", "").replace("_", "")
        # Validate string
        if (
            cleaned_string not in self.default_algo_list
            and cleaned_string not in self.other_algo_list
        ):
            raise ValueError(f"Algorithm not supported: {cleaned_string}")
        return cleaned_string

    def computehash(self, stream, algorithm=None):
        """Compute hash of a file-like object using :attr:`algorithm` by default
        or with optional algorithm supported.

        Args:
            stream (io.BufferedReader): A buffered stream of an ab_id object. \n
            algorithm (string): Algorithm of hex digest to generate.

        Returns:
            hex_digest (string): Hex digest.
        """
        if algorithm is None:
            hashobj = hashlib.new(self.algorithm)
        else:
            check_algorithm = self.clean_algorithm(algorithm)
            hashobj = hashlib.new(check_algorithm)
        for data in stream:
            hashobj.update(self._to_bytes(data))
        hex_digest = hashobj.hexdigest()
        return hex_digest

    def get_store_path(self, entity):
        """Return a path object of the root directory of the store.

        Args:
            entity (str): Desired entity type (ex. "objects", "sysmeta").
        """
        if entity == "objects":
            return Path(self.objects)
        elif entity == "sysmeta":
            return Path(self.sysmeta)
        else:
            raise ValueError(
                f"entity: {entity} does not exist. Do you mean 'objects' or 'sysmeta'?"
            )

    def exists(self, entity, file):
        """Check whether a given file id or path exists on disk.

        Args:
            entity (str): Desired entity type (ex. "objects", "sysmeta"). \n
            file (str): The name of the file to check.

        Returns:
            file_exists (bool): True if the file exists.

        """
        file_exists = bool(self.get_real_path(entity, file))
        return file_exists

    def shard(self, digest):
        """Generates a list given a digest of `self.depth` number of tokens with width
            `self.width` from the first part of the digest plus the remainder.

        Example:
            ['0d', '55', '5e', 'd77052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e']

        Args:
            digest (str): The string to be divided into tokens.

        Returns:
            hierarchical_list (list): A list containing the tokens of fixed width.
        """

        def compact(items):
            """Return only truthy elements of `items`."""
            return [item for item in items if item]

        # This creates a list of `depth` number of tokens with width
        # `width` from the first part of the id plus the remainder.
        hierarchical_list = compact(
            [digest[i * self.width : self.width * (i + 1)] for i in range(self.depth)]
            + [digest[self.depth * self.width :]]
        )

        return hierarchical_list

    def open(self, entity, file, mode="rb"):
        """Return open buffer object from given id or path. Caller is responsible
        for closing the stream.

        Args:
            entity (str): Desired entity type (ex. "objects", "sysmeta"). \n
            file (str): Address ID or path of file. \n
            mode (str, optional): Mode to open file in. Defaults to 'rb'.

        Returns:
            buffer (io.BufferedReader): An `io` stream dependent on the `mode`.
        """
        realpath = self.get_real_path(entity, file)
        if realpath is None:
            raise IOError(f"Could not locate file: {file}")

        # pylint: disable=W1514
        # mode defaults to "rb"
        buffer = io.open(realpath, mode)
        return buffer

    def delete(self, entity, file):
        """Delete file using id or path. Remove any empty directories after
        deleting. No exception is raised if file doesn't exist.

        Args:
            entity (str): Desired entity type (ex. "objects", "sysmeta"). \n
            file (str): Address ID or path of file.
        """
        realpath = self.get_real_path(entity, file)
        if realpath is None:
            return None

        try:
            os.remove(realpath)
        except OSError:
            pass
        else:
            self.remove_empty(os.path.dirname(realpath))

    def remove_empty(self, subpath):
        """Successively remove all empty folders starting with `subpath` and
        proceeding "up" through directory tree until reaching the `root`
        folder.

        Args:
            subpath (str, path): Name of directory.
        """
        # Don't attempt to remove any folders if subpath is not a
        # subdirectory of the root directory.
        if not self._has_subdir(subpath):
            return

        while subpath != self.root:
            if len(os.listdir(subpath)) > 0 or os.path.islink(subpath):
                break
            os.rmdir(subpath)
            subpath = os.path.dirname(subpath)

    def _has_subdir(self, path):
        """Return whether `path` is a subdirectory of the `root` directory.

        Args:
            path (str, path): Name of path.

        Returns:
            is_subdir (boolean): `True` if subdirectory.
        """
        # Append os.sep so that paths like /usr/var2/log doesn't match /usr/var.
        root_path = os.path.realpath(self.root) + os.sep
        subpath = os.path.realpath(path)
        is_subdir = subpath.startswith(root_path)
        return is_subdir

    def create_path(self, path):
        """Physically create the folder path on disk.

        Args:
            path (str): The path to create.

        Raises:
            AssertionError (exception): If the path already exists but is not a directory.
        """
        try:
            os.makedirs(path, self.dmode)
        except FileExistsError:
            assert os.path.isdir(path), f"expected {path} to be a directory"

    def get_real_path(self, entity, file):
        """Attempt to determine the real path of a file id or path through
        successive checking of candidate paths. If the real path is stored with
        an extension, the path is considered a match if the basename matches
        the expected file path of the id.

        Args:
            entity (str): desired entity type (ex. "objects", "sysmeta"). \n
            file (string): Name of file.

        Returns:
            exists (boolean): Whether file is found or not.
        """
        # Check for absolute path.
        if os.path.isfile(file):
            return file

        # Check for relative path.
        rel_root = ""
        if entity == "objects":
            rel_root = self.objects
        elif entity == "sysmeta":
            rel_root = self.sysmeta
        else:
            raise ValueError(
                f"entity: {entity} does not exist. Do you mean 'objects' or 'sysmeta'?"
            )
        relpath = os.path.join(rel_root, file)
        if os.path.isfile(relpath):
            return relpath

        # Check for sharded path.
        abspath = self.build_abs_path(entity, file)
        if os.path.isfile(abspath):
            return abspath

        # Could not determine a match.
        return None

    def build_abs_path(self, entity, ab_id, extension=""):
        """Build the absolute file path for a given hash id with an optional file extension.

        Args:
            entity (str): Desired entity type (ex. "objects", "sysmeta"). \n
            ab_id (str): A hash id to build a file path for. \n
            extension (str): An optional file extension to append to the file path.

        Returns:
            absolute_path (str): An absolute file path for the specified hash id.
        """
        paths = self.shard(ab_id)
        root_dir = self.get_store_path(entity)

        if extension and not extension.startswith(os.extsep):
            extension = os.extsep + extension
        elif not extension:
            extension = ""

        absolute_path = os.path.join(root_dir, *paths) + extension
        return absolute_path

    def count(self, entity):
        """Return count of the number of files in the `root` directory.

        Args:
            entity (str): Desired entity type (ex. "objects", "sysmeta").

        Returns:
            count (int): Number of files in the directory.
        """
        count = 0
        directory_to_count = ""
        if entity == "objects":
            directory_to_count = self.objects
        elif entity == "sysmeta":
            directory_to_count = self.sysmeta
        else:
            raise ValueError(
                f"entity: {entity} does not exist. Do you mean 'objects' or 'sysmeta'?"
            )

        for _, _, files in os.walk(directory_to_count):
            for _ in files:
                count += 1
        return count

    # Static Methods

    @staticmethod
    def _to_bytes(text):
        """Convert text to sequence of bytes using utf-8 encoding.

        Args:
            text (str): String to convert.

        Returns:
            text (bytes): Bytes with utf-8 encoding.
        """
        if not isinstance(text, bytes):
            text = bytes(text, "utf8")
        return text

    @staticmethod
    def get_sha256_hex_digest(string):
        """Calculate the SHA-256 digest of a UTF-8 encoded string.

        Args:
            string (string): String to convert.

        Returns:
            hex (string): Hexadecimal string.
        """
        hex_digest = hashlib.sha256(string.encode("utf-8")).hexdigest()
        return hex_digest


class Stream(object):
    """Common interface for file-like objects.

    The input `obj` can be a file-like object or a path to a file. If `obj` is
    a path to a file, then it will be opened until :meth:`close` is called.
    If `obj` is a file-like object, then its original position will be
    restored when :meth:`close` is called instead of closing the object
    automatically. Closing of the stream is deferred to whatever process passed
    the stream in.

    Successive readings of the stream is supported without having to manually
    set it's position back to ``0``.
    """

    def __init__(self, obj):
        if hasattr(obj, "read"):
            pos = obj.tell()
        elif os.path.isfile(obj):
            obj = io.open(obj, "rb")
            pos = None
        else:
            raise ValueError("Object must be a valid file path or a readable object")

        try:
            file_stat = os.stat(obj.name)
            buffer_size = file_stat.st_blksize
        except (FileNotFoundError, PermissionError, OSError):
            buffer_size = 8192

        self._obj = obj
        self._pos = pos
        self._buffer_size = buffer_size

    def __iter__(self):
        """Read underlying IO object and yield results. Return object to
        original position if we didn't open it originally.
        """
        self._obj.seek(0)

        while True:
            data = self._obj.read(self._buffer_size)

            if not data:
                break

            yield data

        if self._pos is not None:
            self._obj.seek(self._pos)

    def close(self):
        """Close underlying IO object if we opened it, else return it to
        original position.
        """
        if self._pos is None:
            self._obj.close()
        else:
            self._obj.seek(self._pos)
