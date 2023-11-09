"""Core module for FileHashStore"""
import atexit
import io
import shutil
import threading
import time
import hashlib
import os
import logging
from pathlib import Path
from contextlib import closing
from tempfile import NamedTemporaryFile
import yaml
from hashstore import HashStore, ObjectMetadata


class FileHashStore(HashStore):
    """FileHashStore is a content addressable file manager based on Derrick
    Gilland's 'hashfs' library. It supports the storage of objects on disk using
    an authority-based identifier's hex digest with a given hash algorithm value
    to address files.

    FileHashStore initializes using a given properties dictionary containing the
    required keys (see Args). Upon initialization, FileHashStore verifies the provided
    properties and attempts to write a configuration file 'hashstore.yaml' to the given
    store path directory. Properties must always be supplied to ensure consistent
    usage of FileHashStore once configured.

    Args:
        properties (dict): A python dictionary with the following keys (and values):
            store_path (str): Path to the HashStore directory.
            store_depth (int): Depth when sharding an object's hex digest.
            store_width (int): Width of directories when sharding an object's hex digest.
            store_algorithm (str): Hash algorithm used for calculating the object's hex digest.
            store_metadata_namespace (str): Namespace for the HashStore's system metadata.
    """

    # Property (hashstore configuration) requirements
    property_required_keys = [
        "store_path",
        "store_depth",
        "store_width",
        "store_algorithm",
        "store_metadata_namespace",
    ]
    # Permissions settings for writing files and creating directories
    fmode = 0o664
    dmode = 0o755
    # The other algorithm list consists of additional algorithms that can be included
    # for calculating when storing objects, in addition to the default list.
    other_algo_list = [
        "sha224",
        "sha3_224",
        "sha3_256",
        "sha3_384",
        "sha3_512",
        "blake2b",
        "blake2s",
    ]
    # Variables to orchestrate thread locking and object store synchronization
    time_out_sec = 1
    object_lock = threading.Lock()
    metadata_lock = threading.Lock()
    object_locked_pids = []
    metadata_locked_pids = []

    def __init__(self, properties=None):
        if properties:
            # Validate properties against existing configuration if present
            checked_properties = self._validate_properties(properties)
            (
                prop_store_path,
                prop_store_depth,
                prop_store_width,
                _,
                prop_store_metadata_namespace,
            ) = [
                checked_properties[property_name]
                for property_name in self.property_required_keys
            ]

            # Check to see if a configuration is present in the given store path
            self.hashstore_configuration_yaml = prop_store_path + "/hashstore.yaml"
            self._verify_hashstore_properties(properties, prop_store_path)

            # If no exceptions thrown, FileHashStore ready for initialization
            logging.debug("FileHashStore - Initializing, properties verified.")
            self.root = prop_store_path
            if not os.path.exists(self.root):
                self.create_path(self.root)
            self.depth = prop_store_depth
            self.width = prop_store_width
            self.sysmeta_ns = prop_store_metadata_namespace
            # Write 'hashstore.yaml' to store path
            if not os.path.exists(self.hashstore_configuration_yaml):
                # pylint: disable=W1201
                logging.debug(
                    "FileHashStore - HashStore does not exist & configuration file not found."
                    + " Writing configuration file."
                )
                self.write_properties(properties)
            # Default algorithm list for FileHashStore based on config file written
            self._set_default_algorithms()
            # Complete initialization/instantiation by setting and creating store directories
            self.objects = self.root + "/objects"
            self.metadata = self.root + "/metadata"
            if not os.path.exists(self.objects):
                self.create_path(self.objects + "/tmp")
            if not os.path.exists(self.metadata):
                self.create_path(self.metadata + "/tmp")
            logging.debug(
                "FileHashStore - Initialization success. Store root: %s", self.root
            )
        else:
            # Cannot instantiate or initialize FileHashStore without config
            exception_string = (
                "FileHashStore - HashStore properties must be supplied."
                + f" Properties: {properties}"
            )
            logging.debug(exception_string)
            raise ValueError(exception_string)

    # Configuration and Related Methods

    def load_properties(self):
        """Get and return the contents of the current HashStore configuration.

        Returns:
            hashstore_yaml_dict (dict): HashStore properties with the following keys (and values):
                store_depth (int): Depth when sharding an object's hex digest.
                store_width (int): Width of directories when sharding an object's hex digest.
                store_algorithm (str): Hash algorithm used for calculating the object's hex digest.
                store_metadata_namespace (str): Namespace for the HashStore's system metadata.
        """
        if not os.path.exists(self.hashstore_configuration_yaml):
            exception_string = (
                "FileHashStore - load_properties: hashstore.yaml not found"
                + " in store root path."
            )
            logging.critical(exception_string)
            raise FileNotFoundError(exception_string)
        # Open file
        with open(self.hashstore_configuration_yaml, "r", encoding="utf-8") as file:
            yaml_data = yaml.safe_load(file)

        # Get hashstore properties
        hashstore_yaml_dict = {}
        for key in self.property_required_keys:
            if key is not "store_path":
                hashstore_yaml_dict[key] = yaml_data[key]
        logging.debug(
            "FileHashStore - load_properties: Successfully retrieved 'hashstore.yaml' properties."
        )
        return hashstore_yaml_dict

    def write_properties(self, properties):
        """Writes 'hashstore.yaml' to FileHashStore's root directory with the respective
        properties object supplied.

        Args:
            properties (dict): A python dictionary with the following keys (and values):
                store_depth (int): Depth when sharding an object's hex digest.
                store_width (int): Width of directories when sharding an object's hex digest.
                store_algorithm (str): Hash algorithm used for calculating the object's hex digest.
                store_metadata_namespace (str): Namespace for the HashStore's system metadata.
        """
        # If hashstore.yaml already exists, must throw exception and proceed with caution
        if os.path.exists(self.hashstore_configuration_yaml):
            exception_string = (
                "FileHashStore - write_properties: configuration file 'hashstore.yaml'"
                + " already exists."
            )
            logging.error(exception_string)
            raise FileExistsError(exception_string)
        # Validate properties
        checked_properties = self._validate_properties(properties)

        # Collect configuration properties from validated & supplied dictionary
        (
            _,
            store_depth,
            store_width,
            store_algorithm,
            store_metadata_namespace,
        ) = [
            checked_properties[property_name]
            for property_name in self.property_required_keys
        ]

        # Standardize algorithm value for cross-language compatibility
        checked_store_algorithm = None
        # Note, this must be declared here because HashStore has not yet been initialized
        accepted_store_algorithms = ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"]
        if store_algorithm in accepted_store_algorithms:
            checked_store_algorithm = store_algorithm
        else:
            exception_string = (
                f"FileHashStore - write_properties: algorithm supplied ({store_algorithm})"
                + " cannot be used as default for HashStore. Must be one of:"
                + " MD5, SHA-1, SHA-256, SHA-384, SHA-512 which are DataONE"
                + " controlled algorithm values"
            )
            logging.error(exception_string)
            raise ValueError(exception_string)

        # .yaml file to write
        hashstore_configuration_yaml = self._build_hashstore_yaml_string(
            store_depth,
            store_width,
            checked_store_algorithm,
            store_metadata_namespace,
        )
        # Write 'hashstore.yaml'
        with open(
            self.hashstore_configuration_yaml, "w", encoding="utf-8"
        ) as hashstore_yaml:
            hashstore_yaml.write(hashstore_configuration_yaml)

        logging.debug(
            "FileHashStore - write_properties: Configuration file written to: %s",
            self.hashstore_configuration_yaml,
        )
        return

    @staticmethod
    def _build_hashstore_yaml_string(
        store_depth, store_width, store_algorithm, store_metadata_namespace
    ):
        """Build a YAML string representing the configuration for a HashStore.

        Args:
            store_path (str): Path to the HashStore directory.
            store_depth (int): Depth when sharding an object's hex digest.
            store_width (int): Width of directories when sharding an object's hex digest.
            store_algorithm (str): Hash algorithm used for calculating the object's hex digest.
            store_metadata_namespace (str): Namespace for the HashStore's system metadata.

        Returns:
            hashstore_configuration_yaml (str): A YAML string representing the configuration for
            a HashStore.
        """
        hashstore_configuration_yaml = f"""
        # Default configuration variables for HashStore

        ############### Directory Structure ###############
        # Desired amount of directories when sharding an object to form the permanent address
        store_depth: {store_depth}  # WARNING: DO NOT CHANGE UNLESS SETTING UP NEW HASHSTORE
        # Width of directories created when sharding an object to form the permanent address
        store_width: {store_width}  # WARNING: DO NOT CHANGE UNLESS SETTING UP NEW HASHSTORE
        # Example:
        # Below, objects are shown listed in directories that are 3 levels deep (DIR_DEPTH=3),
        # with each directory consisting of 2 characters (DIR_WIDTH=2).
        #    /var/filehashstore/objects
        #    ├── 7f
        #    │   └── 5c
        #    │       └── c1
        #    │           └── 8f0b04e812a3b4c8f686ce34e6fec558804bf61e54b176742a7f6368d6

        ############### Format of the Metadata ###############
        # The default metadata format
        store_metadata_namespace: "{store_metadata_namespace}"

        ############### Hash Algorithms ###############
        # Hash algorithm to use when calculating object's hex digest for the permanent address
        store_algorithm: "{store_algorithm}"
        # Algorithm values supported by python hashlib 3.9.0+ for File Hash Store (FHS)
        # The default algorithm list includes the hash algorithms calculated when storing an
        # object to disk and returned to the caller after successful storage.
        store_default_algo_list:
        - "MD5"
        - "SHA-1"
        - "SHA-256"
        - "SHA-384"
        - "SHA-512"
        """
        return hashstore_configuration_yaml

    def _verify_hashstore_properties(self, properties, prop_store_path):
        """Determines whether FileHashStore can instantiate by validating a set of arguments
        and throwing exceptions. HashStore will not instantiate if an existing configuration
        file's properties (`hashstore.yaml`) are different from what is supplied - or if an
        object store exists at the given path, but it is missing the `hashstore.yaml` config file.

        If `hashstore.yaml` exists, it will retrieve its properties and compare them with the
        given values; and if there is a mismatch, an exception will be thrown. If not, it will
        look to see if any directories/files exist in the given store path and throw an exception
        if any file or directory is found.

        Args:
            properties (dict): HashStore properties
            prop_store_path (string): Store path to check
        """
        if os.path.exists(self.hashstore_configuration_yaml):
            logging.debug(
                "FileHashStore - Config found (hashstore.yaml) at {%s}. Verifying properties.",
                self.hashstore_configuration_yaml,
            )
            # If 'hashstore.yaml' is found, verify given properties before init
            hashstore_yaml_dict = self.load_properties()
            for key in self.property_required_keys:
                # 'store_path' is required to init HashStore but not saved in `hashstore.yaml`
                if key is not "store_path":
                    supplied_key = properties[key]
                    if key == "store_depth" or key == "store_width":
                        supplied_key = int(properties[key])
                    if hashstore_yaml_dict[key] != supplied_key:
                        exception_string = (
                            f"FileHashStore - Given properties ({key}: {properties[key]}) does not"
                            + f" match. HashStore configuration ({key}: {hashstore_yaml_dict[key]})"
                            + f" found at: {self.hashstore_configuration_yaml}"
                        )
                        logging.critical(exception_string)
                        raise ValueError(exception_string)
        else:
            if os.path.exists(prop_store_path):
                # Check if HashStore exists and throw exception if found
                if any(Path(prop_store_path).iterdir()):
                    exception_string = (
                        "FileHashStore - HashStore directories and/or objects found at:"
                        + f" {prop_store_path} but missing configuration file at: "
                        + self.hashstore_configuration_yaml
                    )
                    logging.critical(exception_string)
                    raise FileNotFoundError(exception_string)

    def _validate_properties(self, properties):
        """Validate a properties dictionary by checking if it contains all the
        required keys and non-None values.

        Args:
            properties (dict): Dictionary containing filehashstore properties.

        Raises:
            KeyError: If key is missing from the required keys.
            ValueError: If value is missing for a required key.

        Returns:
            properties (dict): The given properties object (that has been validated).
        """
        if not isinstance(properties, dict):
            exception_string = (
                "FileHashStore - _validate_properties: Invalid argument -"
                + " expected a dictionary."
            )
            logging.debug(exception_string)
            raise ValueError(exception_string)

        for key in self.property_required_keys:
            if key not in properties:
                exception_string = (
                    "FileHashStore - _validate_properties: Missing required"
                    + f" key: {key}."
                )
                logging.debug(exception_string)
                raise KeyError(exception_string)
            if properties.get(key) is None:
                exception_string = (
                    "FileHashStore - _validate_properties: Value for key:"
                    + f" {key} is none."
                )
                logging.debug(exception_string)
                raise ValueError(exception_string)
        return properties

    def _set_default_algorithms(self):
        """Set the default algorithms to calculate when storing objects."""

        def lookup_algo(algo):
            """Translate DataONE controlled algorithms to python hashlib values:
            https://dataoneorg.github.io/api-documentation/apis/Types.html#Types.ChecksumAlgorithm
            """
            dataone_algo_translation = {
                "MD5": "md5",
                "SHA-1": "sha1",
                "SHA-256": "sha256",
                "SHA-384": "sha384",
                "SHA-512": "sha512",
            }
            return dataone_algo_translation[algo]

        if not os.path.exists(self.hashstore_configuration_yaml):
            exception_string = (
                "FileHashStore - set_default_algorithms: hashstore.yaml not found"
                + " in store root path."
            )
            logging.critical(exception_string)
            raise FileNotFoundError(exception_string)
        with open(self.hashstore_configuration_yaml, "r", encoding="utf-8") as file:
            yaml_data = yaml.safe_load(file)

        # Set default store algorithm
        self.algorithm = lookup_algo(yaml_data["store_algorithm"])
        # Takes DataOne controlled algorithm values and translates to hashlib supported values
        yaml_store_default_algo_list = yaml_data["store_default_algo_list"]
        translated_default_algo_list = []
        for algo in yaml_store_default_algo_list:
            translated_default_algo_list.append(lookup_algo(algo))

        # Set class variable
        self.default_algo_list = translated_default_algo_list
        return

    # Public API / HashStore Interface Methods

    def store_object(
        self,
        pid=None,
        data=None,
        additional_algorithm=None,
        checksum=None,
        checksum_algorithm=None,
        expected_object_size=None,
    ):
        logging.debug(
            "FileHashStore - store_object: Request to store object for pid: %s", pid
        )
        # Validate input parameters
        self._is_string_none_or_empty(pid, "pid", "store_object")
        self._validate_data_to_store(data)
        self._validate_file_size(expected_object_size)
        (
            additional_algorithm_checked,
            checksum_algorithm_checked,
        ) = self._validate_algorithms_and_checksum(
            additional_algorithm, checksum, checksum_algorithm
        )

        # Wait for the pid to release if it's in use
        while pid in self.object_locked_pids:
            logging.debug(
                "FileHashStore - store_object: %s is currently being stored. Waiting.",
                pid,
            )
            time.sleep(self.time_out_sec)
        # Modify object_locked_pids consecutively
        with self.object_lock:
            logging.debug(
                "FileHashStore - store_object: Adding pid: %s to object_locked_pids.",
                pid,
            )
            self.object_locked_pids.append(pid)
        try:
            logging.debug(
                "FileHashStore - store_object: Attempting to store object for pid: %s",
                pid,
            )
            object_metadata = self.put_object(
                pid,
                data,
                additional_algorithm=additional_algorithm_checked,
                checksum=checksum,
                checksum_algorithm=checksum_algorithm_checked,
                file_size_to_validate=expected_object_size,
            )
        finally:
            # Release pid
            with self.object_lock:
                logging.debug(
                    "FileHashStore - store_object: Removing pid: %s from object_locked_pids.",
                    pid,
                )
                self.object_locked_pids.remove(pid)
            logging.info(
                "FileHashStore - store_object: Successfully stored object for pid: %s",
                pid,
            )

        return object_metadata

    def store_metadata(self, pid, metadata, format_id=None):
        logging.debug(
            "FileHashStore - store_metadata: Request to store metadata for pid: %s", pid
        )
        # Validate input parameters
        self._is_string_none_or_empty(pid, "pid", "store_metadata")
        checked_format_id = self._validate_format_id(format_id, "store_metadata")
        self._validate_metadata_to_store(metadata)

        # Wait for the pid to release if it's in use
        while pid in self.metadata_locked_pids:
            logging.debug(
                "FileHashStore - store_metadata: %s is currently being stored. Waiting.",
                pid,
            )
            time.sleep(self.time_out_sec)

        with self.metadata_lock:
            logging.debug(
                "FileHashStore - store_metadata: Adding pid: %s to metadata_locked_pids.",
                pid,
            )
            # Modify metadata_locked_pids consecutively
            self.metadata_locked_pids.append(pid)

        try:
            logging.debug(
                "FileHashStore - store_metadata: Attempting to store metadata for pid: %s",
                pid,
            )
            metadata_cid = self.put_metadata(metadata, pid, checked_format_id)
        finally:
            # Release pid
            with self.metadata_lock:
                logging.debug(
                    "FileHashStore - store_metadata: Removing pid: %s from metadata_locked_pids.",
                    pid,
                )
                self.metadata_locked_pids.remove(pid)
            logging.info(
                "FileHashStore - store_metadata: Successfully stored metadata for pid: %s",
                pid,
            )

        return metadata_cid

    def retrieve_object(self, pid):
        logging.debug(
            "FileHashStore - retrieve_object: Request to retrieve object for pid: %s",
            pid,
        )
        self._is_string_none_or_empty(pid, "pid", "retrieve_object")

        entity = "objects"
        object_cid = self.get_sha256_hex_digest(pid)
        object_exists = self.exists(entity, object_cid)

        if object_exists:
            logging.debug(
                "FileHashStore - retrieve_object: Metadata exists for pid: %s, retrieving object.",
                pid,
            )
            obj_stream = self.open(entity, object_cid)
        else:
            exception_string = (
                f"FileHashStore - retrieve_object: No object found for pid: {pid}"
            )
            logging.error(exception_string)
            raise ValueError(exception_string)
        logging.info(
            "FileHashStore - retrieve_object: Retrieved object for pid: %s", pid
        )

        return obj_stream

    def retrieve_metadata(self, pid, format_id=None):
        logging.debug(
            "FileHashStore - retrieve_metadata: Request to retrieve metadata for pid: %s",
            pid,
        )
        self._is_string_none_or_empty(pid, "pid", "retrieve_metadata")
        checked_format_id = self._validate_format_id(format_id, "retrieve_metadata")

        entity = "metadata"
        metadata_cid = self.get_sha256_hex_digest(pid + checked_format_id)
        metadata_exists = self.exists(entity, metadata_cid)
        if metadata_exists:
            metadata_stream = self.open(entity, metadata_cid)
        else:
            exception_string = (
                f"FileHashStore - retrieve_metadata: No metadata found for pid: {pid}"
            )
            logging.error(exception_string)
            raise ValueError(exception_string)

        logging.info(
            "FileHashStore - retrieve_metadata: Retrieved metadata for pid: %s", pid
        )
        return metadata_stream

    def delete_object(self, pid):
        logging.debug(
            "FileHashStore - delete_object: Request to delete object for pid: %s", pid
        )
        self._is_string_none_or_empty(pid, "pid", "delete_object")

        entity = "objects"
        object_cid = self.get_sha256_hex_digest(pid)
        self.delete(entity, object_cid)

        logging.info(
            "FileHashStore - delete_object: Successfully deleted object for pid: %s",
            pid,
        )
        return True

    def delete_metadata(self, pid, format_id=None):
        logging.debug(
            "FileHashStore - delete_metadata: Request to delete metadata for pid: %s",
            pid,
        )
        self._is_string_none_or_empty(pid, "pid", "delete_metadata")
        checked_format_id = self._validate_format_id(format_id, "delete_metadata")

        entity = "metadata"
        metadata_cid = self.get_sha256_hex_digest(pid + checked_format_id)
        self.delete(entity, metadata_cid)

        logging.info(
            "FileHashStore - delete_metadata: Successfully deleted metadata for pid: %s",
            pid,
        )
        return True

    def get_hex_digest(self, pid, algorithm):
        logging.debug(
            "FileHashStore - get_hex_digest: Request to get hex digest for object with pid: %s",
            pid,
        )
        self._is_string_none_or_empty(pid, "pid", "get_hex_digest")
        self._is_string_none_or_empty(algorithm, "algorithm", "get_hex_digest")

        entity = "objects"
        algorithm = self.clean_algorithm(algorithm)
        object_cid = self.get_sha256_hex_digest(pid)
        if not self.exists(entity, object_cid):
            exception_string = (
                f"FileHashStore - get_hex_digest: No object found for pid: {pid}"
            )
            logging.error(exception_string)
            raise ValueError(exception_string)
        cid_stream = self.open(entity, object_cid)
        hex_digest = self.computehash(cid_stream, algorithm=algorithm)

        info_msg = (
            f"FileHashStore - get_hex_digest: Successfully calculated hex digest for pid: {pid}."
            + f" Hex Digest: {hex_digest}",
        )
        logging.info(info_msg)
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
        file_size_to_validate=None,
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
            checksum_algorithm (str, optional): Algorithm value of given checksum. \n
            file_size_to_validate (bytes, optional): Expected size of object

        Returns:
            object_metadata (ObjectMetadata): object that contains the object id,
            object file size, duplicate file boolean and hex digest dictionary.
        """
        stream = Stream(file)

        logging.debug(
            "FileHashStore - put_object: Request to put object for pid: %s", pid
        )
        with closing(stream):
            (
                object_cid,
                obj_file_size,
                hex_digest_dict,
            ) = self._move_and_get_checksums(
                pid,
                stream,
                extension,
                additional_algorithm,
                checksum,
                checksum_algorithm,
                file_size_to_validate,
            )

        object_metadata = ObjectMetadata(object_cid, obj_file_size, hex_digest_dict)
        logging.debug(
            "FileHashStore - put_object: Successfully put object for pid: %s",
            pid,
        )
        return object_metadata

    def _move_and_get_checksums(
        self,
        pid,
        stream,
        extension=None,
        additional_algorithm=None,
        checksum=None,
        checksum_algorithm=None,
        file_size_to_validate=None,
    ):
        """Copy the contents of `stream` onto disk with an optional file
        extension appended. The copy process uses a temporary file to store the
        initial contents and returns a dictionary of algorithms and their
        hex digest values. If the file already exists, the method will immediately
        raise an exception. If an algorithm and checksum is provided, it will proceed to
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
            file_size_to_validate (bytes, optional): Expected size of object

        Returns:
            object_metadata (tuple): object id, object file size, duplicate file
            boolean and hex digest dictionary.
        """
        entity = "objects"
        object_cid = self.get_sha256_hex_digest(pid)
        abs_file_path = self.build_abs_path(entity, object_cid, extension)

        # Only create tmp file to be moved if target destination doesn't exist
        if os.path.isfile(abs_file_path):
            exception_string = (
                "FileHashStore - _move_and_get_checksums: File already exists"
                + f" for pid: {pid} at {abs_file_path}"
            )
            logging.error(exception_string)
            raise FileExistsError(exception_string)

        # Create temporary file and calculate hex digests
        debug_msg = (
            "FileHashStore - _move_and_get_checksums: Creating temp"
            + f" file and calculating checksums for pid: {pid}"
        )
        logging.debug(debug_msg)
        hex_digests, tmp_file_name, tmp_file_size = self._mktmpfile(
            stream, additional_algorithm, checksum_algorithm
        )
        logging.debug(
            "FileHashStore - _move_and_get_checksums: Temp file created: %s",
            tmp_file_name,
        )

        # Only move file if it doesn't exist.
        # Files are stored once and only once
        if not os.path.isfile(abs_file_path):
            self._validate_object(
                pid,
                checksum,
                checksum_algorithm,
                entity,
                hex_digests,
                tmp_file_name,
                tmp_file_size,
                file_size_to_validate,
            )
            self.create_path(os.path.dirname(abs_file_path))
            try:
                debug_msg = (
                    "FileHashStore - _move_and_get_checksums: Moving temp file to permanent"
                    + f" location: {abs_file_path}",
                )
                logging.debug(debug_msg)
                shutil.move(tmp_file_name, abs_file_path)
            except Exception as err:
                # Revert storage process
                exception_string = (
                    "FileHashStore - _move_and_get_checksums:"
                    + f" Unexpected {err=}, {type(err)=}"
                )
                logging.error(exception_string)
                if os.path.isfile(abs_file_path):
                    # Check to see if object has moved successfully before deleting
                    debug_msg = (
                        "FileHashStore - _move_and_get_checksums: Permanent file"
                        + f" found during exception, checking hex digest for pid: {pid}"
                    )
                    logging.debug(debug_msg)
                    pid_checksum = self.get_hex_digest(pid, self.algorithm)
                    if pid_checksum == hex_digests.get(self.algorithm):
                        # If the checksums match, return and log warning
                        warning_msg = (
                            "FileHashStore - _move_and_get_checksums: File moved"
                            + f" successfully but unexpected issue encountered: {exception_string}",
                        )
                        logging.warning(warning_msg)
                        return
                    else:
                        debug_msg = (
                            "FileHashStore - _move_and_get_checksums: Permanent file"
                            + f" found but with incomplete state, deleting file: {abs_file_path}",
                        )
                        logging.debug(debug_msg)
                        self.delete(entity, abs_file_path)
                logging.debug(
                    "FileHashStore - _move_and_get_checksums: Deleting temporary file: %s",
                    tmp_file_name,
                )
                self.delete(entity, tmp_file_name)
                err_msg = (
                    "Aborting store_object upload - an unexpected error has occurred when moving"
                    + f" file to: {object_cid} - Error: {err}"
                )
                logging.error("FileHashStore - _move_and_get_checksums: %s", err_msg)
                raise
        else:
            # Else delete temporary file
            warning_msg = (
                f"FileHashStore - _move_and_get_checksums: Object exists at: {abs_file_path},"
                + " deleting temporary file."
            )
            logging.warning(warning_msg)
            self.delete(entity, tmp_file_name)

        return (object_cid, tmp_file_size, hex_digests)

    def _mktmpfile(self, stream, additional_algorithm=None, checksum_algorithm=None):
        """Create a named temporary file from a `Stream` object and return its filename
        and a dictionary of its algorithms and hex digests. If an additionak and/or checksum
        algorithm is provided, it will add the respective hex digest to the dictionary.

        Args:
            stream (io.BufferedReader): Object stream.
            algorithm (string): Algorithm of additional hex digest to generate
            checksum_algorithm (string): Algorithm of additional checksum algo to generate

        Returns:
            hex_digest_dict, tmp.name (tuple pack):
                hex_digest_dict (dictionary): Algorithms and their hex digests.
                tmp.name: Name of temporary file created and written into.
        """
        # Review additional hash object to digest and create new list
        algorithm_list_to_calculate = self._refine_algorithm_list(
            additional_algorithm, checksum_algorithm
        )

        tmp_root_path = self.get_store_path("objects") / "tmp"
        # Physically create directory if it doesn't exist
        if os.path.exists(tmp_root_path) is False:
            self.create_path(tmp_root_path)
        tmp = NamedTemporaryFile(dir=tmp_root_path, delete=False)

        # Delete tmp file if python interpreter crashes or thread is interrupted
        # when store_object is called
        def delete_tmp_file():
            if os.path.exists(tmp.name):
                os.remove(tmp.name)

        atexit.register(delete_tmp_file)

        # Ensure tmp file is created with desired permissions
        if self.fmode is not None:
            oldmask = os.umask(0)
            try:
                os.chmod(tmp.name, self.fmode)
            finally:
                os.umask(oldmask)

        logging.debug(
            "FileHashStore - _mktempfile: tmp file created: %s, calculating hex digests.",
            tmp.name,
        )

        tmp_file_completion_flag = False
        try:
            hash_algorithms = [
                hashlib.new(algorithm) for algorithm in algorithm_list_to_calculate
            ]

            # tmp is a file-like object that is already opened for writing by default
            with tmp as tmp_file:
                for data in stream:
                    tmp_file.write(self._to_bytes(data))
                    for hash_algorithm in hash_algorithms:
                        hash_algorithm.update(self._to_bytes(data))
            logging.debug(
                "FileHashStore - _mktempfile: Object stream successfully written to tmp file: %s",
                tmp.name,
            )

            hex_digest_list = [
                hash_algorithm.hexdigest() for hash_algorithm in hash_algorithms
            ]
            hex_digest_dict = dict(zip(algorithm_list_to_calculate, hex_digest_list))
            tmp_file_size = os.path.getsize(tmp.name)
            # Ready for validation and atomic move
            tmp_file_completion_flag = True

            logging.debug("FileHashStore - _mktempfile: Hex digests calculated.")
            return hex_digest_dict, tmp.name, tmp_file_size
        # pylint: disable=W0718
        except Exception as err:
            exception_string = (
                f"FileHashStore - _mktempfile: Unexpected {err=}, {type(err)=}"
            )
            logging.error(exception_string)
            # pylint: disable=W0707,W0719
            raise Exception(exception_string)
        except KeyboardInterrupt:
            exception_string = (
                "FileHashStore - _mktempfile: Keyboard interruption by user."
            )
            logging.error(exception_string)
            if os.path.exists(tmp.name):
                os.remove(tmp.name)
        finally:
            if not tmp_file_completion_flag:
                try:
                    if os.path.exists(tmp.name):
                        os.remove(tmp.name)
                # pylint: disable=W0718
                except Exception as err:
                    exception_string = (
                        f"FileHashStore - _mktempfile: Unexpected {err=} while attempting to"
                        + f" delete tmp file: {tmp.name}, {type(err)=}"
                    )
                    logging.error(exception_string)

    def put_metadata(self, metadata, pid, format_id):
        """Store contents of metadata to `[self.root]/metadata` using the hash of the
        given pid and format_id as the permanent address.

        Args:
            pid (string): Authority-based identifier.
            format_id (string): Metadata format.
            metadata (mixed): String or path to metadata document.

        Returns:
            metadata_cid (string): Address of the metadata document.
        """
        logging.debug(
            "FileHashStore - put_metadata: Request to put metadata for pid: %s", pid
        )
        # Create metadata tmp file and write to it
        metadata_stream = Stream(metadata)
        with closing(metadata_stream):
            metadata_tmp = self._mktmpmetadata(metadata_stream)

        # Get target and related paths (permanent location)
        metadata_cid = self.get_sha256_hex_digest(pid + format_id)
        rel_path = "/".join(self.shard(metadata_cid))
        full_path = self.get_store_path("metadata") / rel_path

        # Move metadata to target path
        if os.path.exists(metadata_tmp):
            try:
                parent = full_path.parent
                parent.mkdir(parents=True, exist_ok=True)
                # Metadata will be replaced if it exists
                shutil.move(metadata_tmp, full_path)
                logging.debug(
                    "FileHashStore - put_metadata: Successfully put metadata for pid: %s",
                    pid,
                )
                return metadata_cid
            except Exception as err:
                exception_string = (
                    f"FileHashStore - put_metadata: Unexpected {err=}, {type(err)=}"
                )
                logging.error(exception_string)
                if os.path.exists(metadata_tmp):
                    # Remove tmp metadata, calling app must re-upload
                    logging.debug(
                        "FileHashStore - put_metadata: Deleting metadata for pid: %s",
                        pid,
                    )
                    self.metadata.delete(metadata_tmp)
                raise
        else:
            exception_string = (
                f"FileHashStore - put_metadata: Attempt to move metadata for pid: {pid}"
                + f", but metadata temp file not found: {metadata_tmp}"
            )
            logging.error(exception_string)
            raise FileNotFoundError(exception_string)

    def _mktmpmetadata(self, stream):
        """Create a named temporary file with `stream` (metadata) and `format_id`.

        Args:
            stream (io.BufferedReader): Metadata stream.
            format_id (string): Format of metadata.

        Returns:
            tmp.name (string): Path/name of temporary file created and written into.
        """
        # Create temporary file in .../{store_path}/tmp
        tmp_root_path = self.get_store_path("metadata") / "tmp"
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
        logging.debug(
            "FileHashStore - _mktmpmetadata: Writing stream to tmp metadata file: %s",
            tmp.name,
        )
        with tmp as tmp_file:
            for data in stream:
                tmp_file.write(self._to_bytes(data))

        logging.debug(
            "FileHashStore - _mktmpmetadata: Successfully written to tmp metadata file: %s",
            tmp.name,
        )
        return tmp.name

    # FileHashStore Utility & Supporting Methods

    def _validate_data_to_store(self, data):
        """Evaluates a data argument to ensure that it is either a string, path or
        stream object before attempting to store it.

        Args:
            data (string, path, stream): object to validate
        """
        if (
            not isinstance(data, str)
            and not isinstance(data, Path)
            and not isinstance(data, io.BufferedIOBase)
        ):
            exception_string = (
                "FileHashStore - store_object: Data must be a path, string or buffered"
                + f" stream type. Data type supplied: {type(data)}"
            )
            logging.error(exception_string)
            raise TypeError(exception_string)
        if isinstance(data, str):
            if data.replace(" ", "") == "":
                exception_string = (
                    "FileHashStore - store_object: Data string cannot be empty."
                )
                logging.error(exception_string)
                raise TypeError(exception_string)

    def _validate_algorithms_and_checksum(
        self, additional_algorithm, checksum, checksum_algorithm
    ):
        """Determines whether calling app has supplied the necessary arguments to validate
        an object with a checksum value

        Args:
            additional_algorithm: value of additional algorithm to calculate
            checksum (string): value of checksum
            checksum_algorithm (string): algorithm of checksum
        """
        additional_algorithm_checked = None
        if additional_algorithm != self.algorithm and additional_algorithm is not None:
            # Set additional_algorithm
            additional_algorithm_checked = self.clean_algorithm(additional_algorithm)
        checksum_algorithm_checked = None
        if checksum is not None:
            self._is_string_none_or_empty(
                checksum_algorithm,
                "checksum_algorithm",
                "validate_checksum_args (store_object)",
            )
        if checksum_algorithm is not None:
            self._is_string_none_or_empty(
                checksum,
                "checksum",
                "validate_checksum_args (store_object)",
            )
            # Set checksum_algorithm
            checksum_algorithm_checked = self.clean_algorithm(checksum_algorithm)
        return additional_algorithm_checked, checksum_algorithm_checked

    def _refine_algorithm_list(self, additional_algorithm, checksum_algorithm):
        """Create the final list of hash algorithms to calculate

        Args:
            additional_algorithm (string)
            checksum_algorithm (string)

        Return:
            algorithm_list_to_calculate (set): De-duplicated list of hash algorithms
        """
        algorithm_list_to_calculate = self.default_algo_list
        if checksum_algorithm is not None:
            self.clean_algorithm(checksum_algorithm)
            if checksum_algorithm in self.other_algo_list:
                debug_additional_other_algo_str = (
                    f"FileHashStore - _mktempfile: checksum algorithm: {checksum_algorithm}"
                    + " found in other_algo_lists, adding to list of algorithms to calculate."
                )
                logging.debug(debug_additional_other_algo_str)
                algorithm_list_to_calculate.append(checksum_algorithm)
        if additional_algorithm is not None:
            self.clean_algorithm(additional_algorithm)
            if additional_algorithm in self.other_algo_list:
                debug_additional_other_algo_str = (
                    f"FileHashStore - _mktempfile: additional algorithm: {additional_algorithm}"
                    + " found in other_algo_lists, adding to list of algorithms to calculate."
                )
                logging.debug(debug_additional_other_algo_str)
                algorithm_list_to_calculate.append(additional_algorithm)

        # Remove duplicates
        algorithm_list_to_calculate = set(algorithm_list_to_calculate)
        return algorithm_list_to_calculate

    def _validate_object(
        self,
        pid,
        checksum,
        checksum_algorithm,
        entity,
        hex_digests,
        tmp_file_name,
        tmp_file_size,
        file_size_to_validate,
    ):
        """Evaluates an object's integrity

        Args:
            pid: For logging purposes
            checksum: Value of checksum
            checksum_algorithm: Algorithm of checksum
            entity: Type of object
            hex_digests: Dictionary of hex digests to select from
            tmp_file_name: Name of tmp file
            tmp_file_size: Size of the tmp file
            file_size_to_validate: Expected size of the object
        """
        if file_size_to_validate is not None and file_size_to_validate > 0:
            if file_size_to_validate != tmp_file_size:
                self.delete(entity, tmp_file_name)
                exception_string = (
                    "FileHashStore - _move_and_get_checksums: Object file size calculated: "
                    + f" {tmp_file_size} does not match with expected size:"
                    + f"{file_size_to_validate}. Tmp file deleted and file not stored for"
                    + f" pid: {pid}"
                )
                logging.error(exception_string)
                raise ValueError(exception_string)
        if checksum_algorithm is not None and checksum is not None:
            hex_digest_stored = hex_digests[checksum_algorithm]
            if hex_digest_stored != checksum:
                self.delete(entity, tmp_file_name)
                exception_string = (
                    "FileHashStore - _move_and_get_checksums: Hex digest and checksum"
                    + f" do not match - file not stored for pid: {pid}. Algorithm:"
                    + f" {checksum_algorithm}. Checksum provided: {checksum} !="
                    + f" HexDigest: {hex_digest_stored}. Tmp file deleted."
                )
                logging.error(exception_string)
                raise ValueError(exception_string)

    def _validate_metadata_to_store(self, metadata):
        """Evaluates a metadata argument to ensure that it is either a string, path or
        stream object before attempting to store it.

        Args:
            metadata (string, path, stream): metadata to validate
        """
        if isinstance(metadata, str):
            if metadata.replace(" ", "") == "":
                exception_string = (
                    "FileHashStore - store_metadata: Given string path to"
                    + " metadata cannot be empty."
                )
                logging.error(exception_string)
                raise TypeError(exception_string)
        if (
            not isinstance(metadata, str)
            and not isinstance(metadata, Path)
            and not isinstance(metadata, io.BufferedIOBase)
        ):
            exception_string = (
                "FileHashStore - store_metadata: Metadata must be a path or string"
                + f" type, data type supplied: {type(metadata)}"
            )
            logging.error(exception_string)
            raise TypeError(exception_string)

    def _validate_format_id(self, format_id, method):
        """Determines the metadata namespace (format_id) to use for storing,
        retrieving and deleting metadata.

        Args:
            format_id (string): Metadata namespace to review
            method (string): Calling method for logging purposes

        Returns:
            checked_format_id (string): Valid metadata namespace
        """
        checked_format_id = None
        if format_id is not None and format_id.replace(" ", "") == "":
            exception_string = f"FileHashStore - {method}: Format_id cannot be empty."
            logging.error(exception_string)
            raise ValueError(exception_string)
        elif format_id is None:
            # Use default value set by hashstore config
            checked_format_id = self.sysmeta_ns
        else:
            checked_format_id = format_id
        return checked_format_id

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
            exception_string = (
                "FileHashStore: clean_algorithm: Algorithm not supported:"
                + cleaned_string
            )
            logging.error(exception_string)
            raise ValueError(exception_string)
        return cleaned_string

    def computehash(self, stream, algorithm=None):
        """Compute hash of a file-like object using :attr:`algorithm` by default
        or with optional algorithm supported.

        Args:
            stream (io.BufferedReader): A buffered stream of an object_cid object. \n
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
            entity (str): Desired entity type: "objects" or "metadata"
        """
        if entity == "objects":
            return Path(self.objects)
        elif entity == "metadata":
            return Path(self.metadata)
        else:
            raise ValueError(
                f"entity: {entity} does not exist. Do you mean 'objects' or 'metadata'?"
            )

    def exists(self, entity, file):
        """Check whether a given file id or path exists on disk.

        Args:
            entity (str): Desired entity type (ex. "objects", "metadata"). \n
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
            entity (str): Desired entity type (ex. "objects", "metadata"). \n
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
            entity (str): Desired entity type (ex. "objects", "metadata"). \n
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
        """Physically create the folder path (and all intermediate ones) on disk.

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
            entity (str): desired entity type (ex. "objects", "metadata"). \n
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
        elif entity == "metadata":
            rel_root = self.metadata
        else:
            raise ValueError(
                f"entity: {entity} does not exist. Do you mean 'objects' or 'metadata'?"
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

    def build_abs_path(self, entity, cid, extension=""):
        """Build the absolute file path for a given hash id with an optional file extension.

        Args:
            entity (str): Desired entity type (ex. "objects", "metadata"). \n
            cid (str): A hash id to build a file path for. \n
            extension (str): An optional file extension to append to the file path.

        Returns:
            absolute_path (str): An absolute file path for the specified hash id.
        """
        paths = self.shard(cid)
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
            entity (str): Desired entity type (ex. "objects", "metadata").

        Returns:
            count (int): Number of files in the directory.
        """
        count = 0
        directory_to_count = ""
        if entity == "objects":
            directory_to_count = self.objects
        elif entity == "metadata":
            directory_to_count = self.metadata
        else:
            raise ValueError(
                f"entity: {entity} does not exist. Do you mean 'objects' or 'metadata'?"
            )

        for _, _, files in os.walk(directory_to_count):
            for _ in files:
                count += 1
        return count

    # Other Static Methods

    @staticmethod
    def _validate_file_size(file_size):
        """Checks whether a file size is > 0 and an int and throws exception if not.

        Args:
            file_size (int): file size to check
        """
        if file_size is not None:
            if not isinstance(file_size, int):
                exception_string = (
                    "FileHashStore - _is_file_size_valid: size given must be an integer."
                    + f" File size: {file_size}. Arg Type: {type(file_size)}."
                )
                logging.error(exception_string)
                raise TypeError(exception_string)
            if file_size < 1 or not isinstance(file_size, int):
                exception_string = (
                    "FileHashStore - _is_file_size_valid: size given must be > 0"
                )
                logging.error(exception_string)
                raise ValueError(exception_string)

    @staticmethod
    def _is_string_none_or_empty(string, arg, method):
        """Checks whether a string is None or empty and throws an exception if so.

        Args:
            string (string): Value to check
            arg (): Name of argument to check
            method (string): Calling method for logging purposes
        """
        if string is None or string.replace(" ", "") == "":
            exception_string = (
                f"FileHashStore - {method}: {arg} cannot be None"
                + f" or empty, {arg}: {string}."
            )
            logging.error(exception_string)
            raise ValueError(exception_string)

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
    set its position back to ``0``.
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
