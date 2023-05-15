"""Core module for hashstore"""
import io
import shutil
import threading
import time
import hashlib
import importlib.metadata
import os
from pathlib import Path
from contextlib import closing
from tempfile import NamedTemporaryFile
from collections import namedtuple


class HashStore:
    """HashStore is a content-addressable file management system that
    utilizes a persistent identifier (PID) in the form of a hex digest
    value to address files."""

    # Class variables
    dir_depth = 3  # The number of directory levels for storing files
    dir_width = 2  # The width of the directory names, in characters
    sysmeta_ns = "http://ns.dataone.org/service/types/v2.0"
    time_out_sec = 1
    object_lock = threading.Lock()
    sysmeta_lock = threading.Lock()
    object_locked_pids = []
    sysmeta_locked_pids = []

    @staticmethod
    def version():
        """Return the version number"""
        __version__ = importlib.metadata.version("hashstore")
        return __version__

    def __init__(self, store_path):
        """Initialize the hashstore"""
        self.store_path = store_path
        self.objects = FileHashStore(
            self.store_path + "/objects",
            depth=self.dir_depth,
            width=self.dir_width,
            algorithm="sha256",
        )
        self.sysmeta = FileHashStore(
            self.store_path + "/sysmeta",
            depth=self.dir_depth,
            width=self.dir_width,
            algorithm="sha256",
        )

    def store_object(
        self,
        pid,
        data,
        additional_algorithm="sha256",
        checksum=None,
        checksum_algorithm=None,
    ):
        """Add a data object to the store. Returns a HashAddress object that contains
        the permanent address, relative file path, absolute file path, duplicate file
        boolean and hex digest dictionary. The supported algorithms list is based on
        algorithms supported in hashlib for Python 3.9. If an algorithm is passed that
        is supported, the hex digest dictionary returned will include the additional
        algorithm & hex digest. A thread lock is utilized to ensure that a file is
        written once and only once.

        Default algorithms and hex digests to return: md5, sha1, sha256, sha384, sha512

        Args:
            pid (string): authority-based identifier
            data (mixed): string or path to object
            additional_algorithm (string): additional hex digest to include
            checksum (string): checksum to validate against
            checksum_algorithm (string): algorithm of supplied checksum

        Returns:
            address (HashAddress): object that contains the permanent address, relative
            file path, absolute file path, duplicate file boolean and hex digest dictionary
        """
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
        if checksum is not None:
            if checksum_algorithm is None or checksum_algorithm.replace(" ", "") == "":
                raise ValueError(
                    "checksum_algorithm cannot be None or empty if checksum is supplied."
                )
        if checksum_algorithm is not None:
            if checksum is None or checksum.replace(" ", "") == "":
                raise ValueError(
                    "checksum cannot be None or empty if checksum_algorithm is supplied."
                )

        # Wait for the pid to release if it's in use
        while pid in self.object_locked_pids:
            time.sleep(self.time_out_sec)
        # Modify sysmeta_locked_pids consecutively
        with self.object_lock:
            self.object_locked_pids.append(pid)
        try:
            hash_address = self._add_object(
                pid,
                data,
                additional_algorithm=additional_algorithm,
                checksum=checksum,
                checksum_algorithm=checksum_algorithm,
            )
        finally:
            # Release pid
            with self.object_lock:
                self.object_locked_pids.remove(pid)
        return hash_address

    def store_sysmeta(self, pid, sysmeta):
        """Add a system metadata object to the store. Multiple calls to this method
        are non-blocking and will be executed in parallel using sysmeta_locked_pids
        for synchronization.

        Args:
            pid (string): authority-based identifier
            sysmeta (mixed): string or path to sysmeta document

        Returns:
            sysmeta_cid (string): address of the sysmeta document
        """
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
            sysmeta_cid = self._set_sysmeta(pid, sysmeta)
        finally:
            # Release pid
            with self.sysmeta_lock:
                self.sysmeta_locked_pids.remove(pid)
        return sysmeta_cid

    def retrieve_object(self, pid):
        """Retrieve an object from HashStore of a given persistent identifier (pid)

        Args:
            pid (string): authority-based identifier

        Returns:
            obj_stream (io.BufferedReader): a buffered stream of an ab_id object
        """
        if pid is None or pid.replace(" ", "") == "":
            raise ValueError(f"Pid cannot be None or empty, pid: {pid}")

        ab_id = self.objects.get_sha256_hex_digest(pid)
        sysmeta_exists = self.sysmeta.exists(ab_id)
        if sysmeta_exists:
            obj_stream = self.objects.open(ab_id)
        else:
            raise ValueError(f"No sysmeta found for pid: {pid}")
        return obj_stream

    def retrieve_sysmeta(self, pid):
        """Returns the sysmeta of a given persistent identifier (pid).

        Args:
            pid (string): authority-based identifier

        Returns:
            sysmeta (string): sysmeta content
        """
        if pid is None or pid.replace(" ", "") == "":
            raise ValueError(f"Pid cannot be None or empty, pid: {pid}")

        ab_id = self.sysmeta.get_sha256_hex_digest(pid)
        sysmeta_exists = self.sysmeta.exists(ab_id)
        if sysmeta_exists:
            sysmeta = self._get_sysmeta(pid)[1]
        else:
            raise ValueError(f"No sysmeta found for pid: {pid}")
        return sysmeta

    def delete_object(self, pid):
        """Deletes an object given the pid.

        Args:
            pid (string): authority-based identifier

        Returns:
            boolean: True upon successful deletion
        """
        if pid is None or pid.replace(" ", "") == "":
            raise ValueError(f"Pid cannot be None or empty, pid: {pid}")

        ab_id = self.objects.get_sha256_hex_digest(pid)
        self.objects.delete(ab_id)
        return True

    def delete_sysmeta(self, pid):
        """Deletes a sysmeta document given the pid.

        Args:
            pid (string): authority-based identifier

        Returns:
            boolean: True upon successful deletion
        """
        if pid is None or pid.replace(" ", "") == "":
            raise ValueError(f"Pid cannot be None or empty, pid: {pid}")

        ab_id = self.sysmeta.get_sha256_hex_digest(pid)
        self.sysmeta.delete(ab_id)
        return True

    def get_hex_digest(self, pid, algorithm):
        """Returns the hex digest of an object based on the hash algorithm
        passed with a given pid.

        Args:
            pid (string): authority-based identifier
            algorithm (string): algorithm of hex digest to generate

        Returns:
            hex_digest (string): hex digest of the object
        """
        if pid is None or pid.replace(" ", "") == "":
            raise ValueError(f"Pid cannot be None or empty, pid: {pid}")
        if algorithm is None or algorithm.replace(" ", "") == "":
            raise ValueError(f"Algorithm cannot be None or empty, pid: {pid}")

        algorithm = self.objects.clean_algorithm(algorithm)
        ab_id = self.objects.get_sha256_hex_digest(pid)
        if not self.objects.exists(ab_id):
            raise ValueError(f"No object found for pid: {pid}")
        c_stream = self.objects.open(ab_id)
        hex_digest = self.objects.computehash(c_stream, algorithm=algorithm)
        return hex_digest

    def _add_object(
        self, pid, data, additional_algorithm, checksum, checksum_algorithm
    ):
        """Add a data blob to the store.

        Args:
            pid (string): authority-based identifier
            data (mixed): string or path to object
            additional_algorithm (string): additional hex digest to include
            checksum (string): checksum to validate against
            checksum_algorithm (string): algorithm of supplied checksum
        Return:
            address (HashAddress): object that contains the permanent address, relative
            file path, absolute file path, duplicate file boolean and hex digest dictionary
        """
        checked_algorithm = self.objects.clean_algorithm(additional_algorithm)
        # If the additional algorithm supplied is the default, do not generate extra
        if checked_algorithm is self.objects.algorithm:
            checked_algorithm = None
        # If a checksum is supplied, ensure that a checksum_algorithm is present and supported
        checked_checksum_algorithm = ""
        if checksum is not None and checksum != "":
            checked_checksum_algorithm = self.objects.clean_algorithm(
                checksum_algorithm
            )

        address = self.objects.put_object(
            pid,
            data,
            additional_algorithm=checked_algorithm,
            checksum=checksum,
            checksum_algorithm=checked_checksum_algorithm,
        )
        return address

    def _set_sysmeta(self, pid, sysmeta):
        """Add a sysmeta document to the store.

        Args:
            pid (string): authority-based identifier
            sysmeta (mixed): string or path to sysmeta document

        Returns:
            sysmeta_cid (string): address of the sysmeta document
        """
        ab_id = self.sysmeta.put_sysmeta(pid, sysmeta, self.sysmeta_ns)
        return ab_id

    def _get_sysmeta(self, pid):
        """Get the sysmeta content of a given pid (persistent identifier)

        Args:
            pid (string): authority-based identifier

        Returns:
            s_content (string): sysmeta content
        """
        ab_id = self.sysmeta.get_sha256_hex_digest(pid)
        s_path = self.sysmeta.open(ab_id)
        s_content = s_path.read().decode("utf-8").split("\x00", 1)
        s_path.close()
        return s_content


class FileHashStore:
    """FileHashStore is a content addressable file manager based on Derrick
    Gilland's 'hashfs' library. It supports the storage of objects on disk using
    an authority-based identifier's hex digest with a given hash algorithm.

    Args:
        root (str): Directory path used as root of storage space.
        depth (int, optional): Depth of subfolders to create when saving a
            file.
        width (int, optional): Width of each subfolder to create when saving a
            file.
        algorithm (str): Hash algorithm to use when computing file hash.
            Algorithm should be available in ``hashlib`` module. Defaults to
            ``'sha256'``.
        fmode (int, optional): File mode permission to set when adding files to
            directory. Defaults to ``0o664`` which allows owner/group to
            read/write and everyone else to read.
        dmode (int, optional): Directory mode permission to set for
            subdirectories. Defaults to ``0o755`` which allows owner/group to
            read/write and everyone else to read and everyone to execute.
    """

    def __init__(
        self, root, depth=4, width=1, algorithm="sha256", fmode=0o664, dmode=0o755
    ):
        self.root = os.path.realpath(root)
        self.objects = self.root + "/objects"
        self.sysmeta = self.root + "/sysmeta"
        self.depth = depth
        self.width = width
        self.algorithm = algorithm
        self.fmode = fmode
        self.dmode = dmode

    # Class variables
    # Algorithm values supported by python hashlib 3.9.0+
    default_algo_list = ["sha1", "sha256", "sha384", "sha512", "md5"]
    other_algo_list = [
        "sha224",
        "sha3_224",
        "sha3_256",
        "sha3_384",
        "sha3_512",
        "blake2b",
        "blake2s",
    ]

    def _get_store_path(self):
        """Return a path object of the root directory of the store."""
        root_directory = Path(self.root)
        return root_directory

    def clean_algorithm(self, algorithm_string):
        """Format a string and ensure that it is supported and compatible with
        the python hashlib library.

        Args:
            algorithm_string (string): algorithm to validate

        Returns:
            cleaned_string (string): hashlib supported algorithm string
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
            stream (io.BufferedReader): a buffered stream of an ab_id object
            algorithm (string): algorithm of hex digest to generate

        Returns:
            hex_digest (string): hex digest
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

    # pylint: disable=W0237
    # Intentional override for `file` and `extension` to adjust signature values
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
            pid (string): authority-based identifier
            file (mixed): Readable object or path to file.
            extension (str, optional): Optional extension to append to file
                when saving.
            additional_algorithm (str, optional): Optional algorithm value to include
                when returning hex digests.
            checksum (str, optional): Optional checksum to validate object
                against hex digest before moving to permanent location.
            checksum_algorithm (str, optional): Algorithm value of given checksum

        Returns:
            hash_address (HashAddress): object that contains the permanent address,
            relative file path, absolute file path, duplicate file boolean and hex
            digest dictionary
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
            pid (string): authority-based identifier
            stream (io.BufferedReader): object stream
            extension (str, optional): Optional extension to append to file
                when saving.
            additional_algorithm (str, optional): Optional algorithm value to include
                when returning hex digests.
            checksum (str, optional): Optional checksum to validate object
                against hex digest before moving to permanent location.
            checksum_algorithm (str, optional): Algorithm value of given checksum

        Returns:
            hash_address (HashAddress): object that contains the permanent address,
            relative file path, absolute file path, duplicate file boolean and hex
            digest dictionary
        """
        ab_id = self.get_sha256_hex_digest(pid)
        abs_file_path = self.idpath(ab_id, extension)
        self.makepath(os.path.dirname(abs_file_path))
        # Only put file if it doesn't exist
        if os.path.isfile(abs_file_path):
            raise FileExistsError(
                f"File already exists for pid: {pid} at {abs_file_path}"
            )
        else:
            rel_file_path = os.path.relpath(abs_file_path, self.root)

        # Create temporary file and calculate hex digests
        hex_digests, tmp_file_name = self._mktempfile(stream, additional_algorithm)

        # Only move file if it doesn't exist.
        # Files are stored once and only once
        if not os.path.isfile(abs_file_path):
            if checksum_algorithm is not None and checksum is not None:
                hex_digest_stored = hex_digests[checksum_algorithm]
                if hex_digest_stored != checksum:
                    self.delete(tmp_file_name)
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
                    self.delete(abs_file_path)
                self.delete(tmp_file_name)
                # TODO: Log exception
                # f"Aborting Upload - an unexpected error has occurred when moving file: {ab_id} - Error: {err}"
                raise
        else:
            # Else delete temporary file
            is_duplicate = True
            self.delete(tmp_file_name)

        return ab_id, rel_file_path, abs_file_path, is_duplicate, hex_digests

    def _mktempfile(self, stream, algorithm=None):
        """Create a named temporary file from a `Stream` object and
        return its filename and a dictionary of its algorithms and hex digests.
        If an algorithm is provided, it will add the respective hex digest to
        the dictionary.

        Args:
            stream (io.BufferedReader): object stream
            algorithm (string): algorithm of additional hex digest to generate

        Returns:
            hex_digest_dict, tmp.name (tuple pack):
                hex_digest_dict (dictionary): algorithms and their hex digests
                tmp.name: Name of temporary file created and written into
        """

        # Create temporary file in .../{store_path}/tmp
        tmp_root_path = self._get_store_path() / "tmp"
        # Physically create directory if it doesn't exist
        if os.path.exists(tmp_root_path) is False:
            self.makepath(tmp_root_path)
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

    def put_sysmeta(self, pid, sysmeta, namespace):
        """Store contents of `sysmeta` on disk using the hash of the given pid

        Args:
            pid (string): authority-based identifier
            sysmeta (mixed): string or path to sysmeta document
            namespace (string): sysmeta format

        Returns:
            ab_id (string): address of the sysmeta document
        """

        # Create tmp file and write to it
        sysmeta_stream = Stream(sysmeta)
        with closing(sysmeta_stream):
            sysmeta_tmp = self._mktmpsysmeta(sysmeta_stream, namespace)

        # Target path (permanent location)
        ab_id = self.get_sha256_hex_digest(pid)
        rel_path = "/".join(self.shard(ab_id))
        full_path = self._get_store_path() / rel_path

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
        """Create a named temporary file with `sysmeta` bytes and `namespace`

        Args:
            stream (io.BufferedReader): sysmeta stream
            namespace (string): format of sysmeta

        Returns:
            tmp.name (string): Name of temporary file created and written into
        """
        # Create temporary file in .../{store_path}/tmp
        tmp_root_path = self._get_store_path() / "tmp"
        # Physically create directory if it doesn't exist
        if os.path.exists(tmp_root_path) is False:
            self.makepath(tmp_root_path)

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

    def open(self, file, mode="rb"):
        """Return open buffer object from given id or path. Caller is responsible
        for closing the stream.

        Args:
            file (str): Address ID or path of file.
            mode (str, optional): Mode to open file in. Defaults to 'rb'.

        Returns:
            buffer (io.BufferedReader): An `io` stream dependent on the `mode`.
        """
        realpath = self.realpath(file)
        if realpath is None:
            raise IOError(f"Could not locate file: {file}")

        # pylint: disable=W1514
        # mode defaults to "rb"
        buffer = io.open(realpath, mode)
        return buffer

    def delete(self, file):
        """Delete file using id or path. Remove any empty directories after
        deleting. No exception is raised if file doesn't exist.

        Args:
            file (str): Address ID or path of file.
        """
        realpath = self.realpath(file)
        if realpath is None:
            return

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
            subpath (str, path): name of directory
        """
        # Don't attempt to remove any folders if subpath is not a
        # subdirectory of the root directory.
        if not self.haspath(subpath):
            return

        while subpath != self.root:
            if len(os.listdir(subpath)) > 0 or os.path.islink(subpath):
                break
            os.rmdir(subpath)
            subpath = os.path.dirname(subpath)

    def haspath(self, path):
        """Return whether `path` is a subdirectory of the `root` directory.

        Args:
            path (str, path): name of path
        """

        def issubdir(subpath, path):
            """Return whether `subpath` is a sub-directory of `path`."""
            # Append os.sep so that paths like /usr/var2/log doesn't match /usr/var.
            path = os.path.realpath(path) + os.sep
            subpath = os.path.realpath(subpath)
            return subpath.startswith(path)

        return issubdir(path, self.root)

    def makepath(self, path):
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

    def exists(self, file):
        """Check whether a given file id or path exists on disk.

        Args:
            file (str): The name of the file to check.

        Returns:
            file_exists (bool): True if the file exists

        """
        file_exists = bool(self.realpath(file))
        return file_exists

    def realpath(self, file):
        """Attempt to determine the real path of a file id or path through
        successive checking of candidate paths. If the real path is stored with
        an extension, the path is considered a match if the basename matches
        the expected file path of the id.

        Args:
            file (string): Name of file

        Returns:
            exists (boolean): Whether file is found or not
        """
        # Check for absolute path.
        if os.path.isfile(file):
            return file

        # Check for relative path.
        relpath = os.path.join(self.root, file)
        if os.path.isfile(relpath):
            return relpath

        # Check for sharded path.
        filepath = self.idpath(file)
        if os.path.isfile(filepath):
            return filepath

        # Could not determine a match.
        return None

    def idpath(self, ab_id, extension=""):
        """Build the absolute file path for a given hash id with an optional file extension.

        Args:
            ab_id (str): A hash id to build a file path for
            extension (str): An optional file extension to append to the file path.

        Returns:
            absolute_path (str): An absolute file path for the specified hash id
        """
        paths = self.shard(ab_id)

        if extension and not extension.startswith(os.extsep):
            extension = os.extsep + extension
        elif not extension:
            extension = ""

        absolute_path = os.path.join(self.root, *paths) + extension
        return absolute_path

    def shard(self, digest):
        """Generates a list given a digest of `self.depth` number of tokens with width
            `self.width` from the first part of the digest plus the remainder.

        Example:
            ['0d', '55', '5e', 'd77052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e']

        Args:
            digest (str): The string to be divided into tokens.

        Returns:
            hierarchical_list (list): A list containing the tokens of fixed width
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

    def count(self):
        """Return count of the number of files in the `root` directory.

        Returns:
            count (int): Number of files in the directory.
        """
        count = 0
        for _, _, files in os.walk(self.root):
            for _ in files:
                count += 1
        return count

    @staticmethod
    def _to_bytes(text):
        """Convert text to sequence of bytes using utf-8 encoding."""
        if not isinstance(text, bytes):
            text = bytes(text, "utf8")
        return text

    @staticmethod
    def get_sha256_hex_digest(string):
        """Calculate the SHA-256 digest of a UTF-8 encoded string.

        Args:
            string (string)

        Returns:
            hex (string): hexadecimal string
        """
        hex_digest = hashlib.sha256(string.encode("utf-8")).hexdigest()
        return hex_digest


class HashAddress(
    namedtuple(
        "HashAddress", ["id", "relpath", "abspath", "is_duplicate", "hex_digests"]
    )
):
    """File address containing file's path on disk and its content hash ID.

    Args:
        ab_id (str): Hash ID (hexdigest) of file contents.
        relpath (str): Relative path location to :attr:`HashFS.root`.
        abspath (str): Absolute path location of file on disk.
        is_duplicate (boolean, optional): Whether the hash address created was
            a duplicate of a previously existing file. Can only be ``True``
            after a put operation. Defaults to ``False``.
        hex_digests (dict, optional): A list of hex digests to validate objects
            (md5, sha1, sha256, sha384, sha512)
    """

    # Default value to prevent dangerous default value
    def __new__(cls, ab_id, relpath, abspath, is_duplicate=False, hex_digests=None):
        return super(HashAddress, cls).__new__(
            cls, ab_id, relpath, abspath, is_duplicate, hex_digests
        )


class Stream(object):
    """Common interface for file-like objects.

    The input `obj` can be a file-like object or a path to a file. If `obj` is
    a path to a file, then it will be opened until :meth:`close` is called.
    If `obj` is a file-like object, then it's original position will be
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
