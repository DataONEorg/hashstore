"""Core module for FileHashStore"""
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
from hashstore import HashStore
from hashstore.hashaddress import HashAddress


class FileHashStore(HashStore):
    """FileHashStore is a content addressable file manager based on Derrick
    Gilland's 'hashfs' library. It supports the storage of objects on disk using
    an authority-based identifier's hex digest with a given hash algorithm value
    to address files.

    FileHashStore initializes by providing a properties dictionary containing the
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
            store_sysmeta_namespace (str): Namespace for the HashStore's system metadata.
    """

    # Property (hashstore configuration) requirements
    property_required_keys = [
        "store_path",
        "store_depth",
        "store_width",
        "store_algorithm",
        "store_sysmeta_namespace",
    ]
    # Permissions settings for writing files and creating directories
    fmode = 0o664
    dmode = 0o755
    # Default and other algorithm list for FileHashStore
    # The default algorithm list includes the hash algorithms calculated when
    # storing an object to disk and returned to the caller after successful storage.
    default_algo_list = ["sha1", "sha256", "sha384", "sha512", "md5"]
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
    sysmeta_lock = threading.Lock()
    object_locked_pids = []
    sysmeta_locked_pids = []

    def __init__(self, properties=None):
        if properties:
            # Validate properties against existing configuration if present
            checked_properties = self._validate_properties(properties)
            (
                prop_store_path,
                prop_store_depth,
                prop_store_width,
                prop_store_algorithm,
                prop_store_sysmeta_namespace,
            ) = [
                checked_properties[property_name]
                for property_name in self.property_required_keys
            ]

            # Check to see if a configuration is present in the given store path
            self.hashstore_configuration_yaml = prop_store_path + "/hashstore.yaml"
            if os.path.exists(self.hashstore_configuration_yaml):
                logging.debug(
                    "FileHashStore - Config found (hashstore.yaml) at {%s}. Verifying properties.",
                    self.hashstore_configuration_yaml,
                )
                # If 'hashstore.yaml' is found, verify given properties before init
                hashstore_yaml_dict = self.get_properties()
                for key in self.property_required_keys:
                    if hashstore_yaml_dict[key] != properties[key]:
                        exception_string = (
                            f"Given properties ({key}: {properties[key]}) does not match "
                            + f"HashStore configuration ({key}: {hashstore_yaml_dict[key]})"
                            + f"found at: {self.hashstore_configuration_yaml}"
                        )
                        logging.critical("FileHashStore - %s", exception_string)
                        raise ValueError(exception_string)
            else:
                # Check if HashStore exists and throw exception if found
                if any(Path(prop_store_path).iterdir()):
                    exception_string = (
                        f"HashStore directories and/or objects found at: {prop_store_path} but"
                        + f" missing configuration file at: {self.hashstore_configuration_yaml}."
                    )
                    logging.critical("FileHashStore - %s", exception_string)
                    raise FileNotFoundError(exception_string)

            logging.debug("FileHashStore - Initializing, properties verified.")
            self.root = prop_store_path
            self.depth = prop_store_depth
            self.width = prop_store_width
            self.algorithm = prop_store_algorithm
            self.sysmeta_ns = prop_store_sysmeta_namespace
            # Write 'hashstore.yaml' to store path
            if not os.path.exists(self.hashstore_configuration_yaml):
                # pylint: disable=W1201
                logging.debug(
                    "FileHashStore - HashStore does not exist & configuration file not found."
                    + " Writing configuration file."
                )
                self.put_properties(properties)
            # Complete initialization/instantiation by setting store directories
            self.objects = self.root + "/objects"
            self.sysmeta = self.root + "/sysmeta"
            logging.debug(
                "FileHashStore - Initialization success. Store root: %s", self.root
            )
        else:
            exception_string = (
                f"HashStore properties must be supplied. Properties: {properties}"
            )
            logging.debug("FileHashStore - %s", exception_string)
            # Cannot instantiate or initialize FileHashStore without config
            raise ValueError(exception_string)

    # Configuration Methods

    def get_properties(self):
        """Get and return the contents of the current HashStore configuration.

        Returns:
            hashstore_yaml_dict (dict): HashStore properties with the following keys/values:
            "store_path", "store_depth", "store_width", "store_algorithm","store_sysmeta_namespace".
        """
        if not os.path.exists(self.hashstore_configuration_yaml):
            exception_string = "hashstore.yaml not found in store root path."
            logging.critical("FileHashStore - get_properties: %s", exception_string)
            raise FileNotFoundError(exception_string)
        # Open file
        with open(self.hashstore_configuration_yaml, "r", encoding="utf-8") as file:
            yaml_data = yaml.safe_load(file)
        # Get hashstore properties
        hashstore_yaml_dict = {}
        for key in self.property_required_keys:
            hashstore_yaml_dict[key] = yaml_data[key]
        logging.debug(
            "FileHashStore - get_properties: Successfully retrieved 'hashstore.yaml' properties."
        )
        return hashstore_yaml_dict

    def put_properties(self, properties):
        """Writes 'hashstore.yaml' to FileHashStore's root directory with the respective
        properties object supplied.

        Args:
            properties (dict): A python dictionary with the following keys (and values):
                store_path (str): Path to the HashStore directory.
                store_depth (int): Depth when sharding an object's hex digest.
                store_width (int): Width of directories when sharding an object's hex digest.
                store_algorithm (str): Hash algorithm used for calculating the object's hex digest.
                store_sysmeta_namespace (str): Namespace for the HashStore's system metadata.
        """
        # If hashstore.yaml already exists, must throw exception and proceed with caution
        if os.path.exists(self.hashstore_configuration_yaml):
            exception_string = (
                "FileHashStore configuration file 'hashstore.yaml' already exists."
            )
            logging.error("FileHashStore - put_properties: %s", exception_string)
            raise FileExistsError(exception_string)
        # Validate properties
        checked_properties = self._validate_properties(properties)

        # Collect configuration properties from validated & supplied dictionary
        (
            store_path,
            store_depth,
            store_width,
            store_algorithm,
            store_sysmeta_namespace,
        ) = [
            checked_properties[property_name]
            for property_name in self.property_required_keys
        ]

        # .yaml file to write
        hashstore_configuration_yaml = self._build_hashstore_yaml_string(
            store_path,
            store_depth,
            store_width,
            store_algorithm,
            store_sysmeta_namespace,
        )
        # Write 'hashstore.yaml'
        with open(
            self.hashstore_configuration_yaml, "w", encoding="utf-8"
        ) as hashstore_yaml:
            hashstore_yaml.write(hashstore_configuration_yaml)
        logging.debug(
            "FileHashStore - put_properties: Configuration file written to: %s",
            self.hashstore_configuration_yaml,
        )
        return

    @staticmethod
    def _build_hashstore_yaml_string(
        store_path, store_depth, store_width, store_algorithm, store_sysmeta_namespace
    ):
        """Build a YAML string representing the configuration for a HashStore.

        Args:
            store_path (str): Path to the HashStore directory.
            store_depth (int): Depth when sharding an object's hex digest.
            store_width (int): Width of directories when sharding an object's hex digest.
            store_algorithm (str): Hash algorithm used for calculating the object's hex digest.
            store_sysmeta_namespace (str): Namespace for the HashStore's system metadata.

        Returns:
            hashstore_configuration_yaml (str): A YAML string representing the configuration for
            a HashStore.
        """
        hashstore_configuration_yaml = f"""
        # Default configuration variables for HashStore

        ############### Store Path ###############
        # Default path for `FileHashStore` if no path is provided
        store_path: "{store_path}"

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
        store_sysmeta_namespace: "{store_sysmeta_namespace}"

        ############### Hash Algorithms ###############
        # Hash algorithm to use when calculating object's hex digest for the permanent address
        store_algorithm: "{store_algorithm}"
        # Algorithm values supported by python hashlib 3.9.0+ for File Hash Store (FHS)
        # The default algorithm list includes the hash algorithms calculated when storing an
        # object to disk and returned to the caller after successful storage.
        filehashstore_default_algo_list:
        - "sha1"
        - "sha256"
        - "sha384"
        - "sha512"
        - "md5"
        # The other algorithm list consists of additional algorithms that can be included for
        # calculating when storing objects, in addition to the default list.
        filehashstore_other_algo_list:
        - "sha224"
        - "sha3_224"
        - "sha3_256"
        - "sha3_384"
        - "sha3_512"
        - "blake2b"
        - "blake2s"
        """
        return hashstore_configuration_yaml

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
            exception_string = "Invalid argument - expected a dictionary."
            logging.debug("FileHashStore - _validate_properties: %s", exception_string)
            raise ValueError(exception_string)
        for key in self.property_required_keys:
            if key not in properties:
                exception_string = f"Missing required key: {key}."
                logging.debug(
                    "FileHashStore - _validate_properties: %s", exception_string
                )
                raise KeyError(exception_string)
            if properties.get(key) is None:
                exception_string = f"Value for key: {key} is none."
                logging.debug(
                    "FileHashStore - _validate_properties: %s", exception_string
                )
                raise ValueError(exception_string)
        return properties

    # Public API / HashStore Interface Methods

    def store_object(
        self,
        pid,
        data,
        additional_algorithm="sha256",
        checksum=None,
        checksum_algorithm=None,
    ):
        logging.debug(
            "FileHashStore - store_object: Request to store object for pid: %s", pid
        )
        # Validate input parameters
        logging.debug("FileHashStore - store_object: Validating arguments.")
        if pid is None or pid.replace(" ", "") == "":
            exception_string = f"Pid cannot be None or empty, pid: {pid}."
            logging.error("FileHashStore - store_object: %s", exception_string)
            raise ValueError(exception_string)
        if (
            not isinstance(data, str)
            and not isinstance(data, Path)
            and not isinstance(data, io.BufferedIOBase)
        ):
            exception_string = (
                "Data must be a path, string or buffered stream type."
                + f" data type supplied: {type(data)}"
            )
            logging.error("FileHashStore - store_object: %s", exception_string)
            raise TypeError(exception_string)
        if isinstance(data, str):
            if data.replace(" ", "") == "":
                exception_string = "Data string cannot be empty."
                logging.error("FileHashStore - store_object: %s", exception_string)
                raise TypeError(exception_string)
        # Format additional algorithm if supplied
        logging.debug(
            "FileHashStore - store_object: Validating algorithm and checksum args."
        )
        additional_algorithm_checked = None
        if additional_algorithm != self.algorithm and additional_algorithm is not None:
            additional_algorithm_checked = self.clean_algorithm(additional_algorithm)
        # Checksum and checksum_algorithm must both be supplied
        if checksum is not None:
            if checksum_algorithm is None or checksum_algorithm.replace(" ", "") == "":
                exception_string = (
                    "checksum_algorithm cannot be None or empty if checksum is"
                    + "supplied."
                )
                logging.error("FileHashStore - store_object: %s", exception_string)
                raise ValueError(exception_string)
        checksum_algorithm_checked = None
        if checksum_algorithm is not None:
            checksum_algorithm_checked = self.clean_algorithm(checksum_algorithm)
            if checksum is None or checksum.replace(" ", "") == "":
                exception_string = (
                    "checksum cannot be None or empty if checksum_algorithm is"
                    + " supplied."
                )
                logging.error("FileHashStore - store_object: %s", exception_string)
                raise ValueError(exception_string)

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
                logging.debug(
                    "FileHashStore - store_object: Removing pid: %s from object_locked_pids.",
                    pid,
                )
                self.object_locked_pids.remove(pid)
            logging.info(
                "FileHashStore - store_object: Successfully stored object for pid: %s",
                pid,
            )
        return hash_address

    def store_sysmeta(self, pid, sysmeta):
        logging.debug(
            "FileHashStore - store_sysmeta: Request to store sysmeta for pid: %s", pid
        )
        # Validate input parameters
        logging.debug("FileHashStore - store_sysmeta: Validating arguments.")
        if pid is None or pid.replace(" ", "") == "":
            exception_string = f"Pid cannot be None or empty, pid: {pid}"
            logging.error("FileHashStore - store_sysmeta: %s", exception_string)
            raise ValueError(exception_string)
        if (
            not isinstance(sysmeta, str)
            and not isinstance(sysmeta, Path)
            and not isinstance(sysmeta, io.BufferedIOBase)
        ):
            exception_string = (
                "Sysmeta must be a path or string type, data type supplied: "
                + {type(sysmeta)}
            )
            logging.error("FileHashStore - store_sysmeta: %s", exception_string)
            raise TypeError(exception_string)
        if isinstance(sysmeta, str):
            if sysmeta.replace(" ", "") == "":
                exception_string = "Given string path to sysmeta cannot be empty."
                logging.error("FileHashStore - store_sysmeta: %s", exception_string)
                raise TypeError(exception_string)

        # Wait for the pid to release if it's in use
        while pid in self.sysmeta_locked_pids:
            logging.debug(
                "FileHashStore - store_sysmeta: %s is currently being stored. Waiting.",
                pid,
            )
            time.sleep(self.time_out_sec)
        # Modify sysmeta_locked_pids consecutively
        with self.sysmeta_lock:
            logging.debug(
                "FileHashStore - store_sysmeta: Adding pid: %s to sysmeta_locked_pids.",
                pid,
            )
            self.sysmeta_locked_pids.append(pid)
        try:
            logging.debug(
                "FileHashStore - store_sysmeta: Attempting to store sysmeta for pid: %s",
                pid,
            )
            sysmeta_cid = self.put_sysmeta(pid, sysmeta)
        finally:
            # Release pid
            with self.sysmeta_lock:
                logging.debug(
                    "FileHashStore - store_sysmeta: Removing pid: %s from sysmeta_locked_pids.",
                    pid,
                )
                self.sysmeta_locked_pids.remove(pid)
            logging.info(
                "FileHashStore - store_sysmeta: Successfully stored sysmeta for pid: %s",
                pid,
            )
        return sysmeta_cid

    def retrieve_object(self, pid):
        logging.debug(
            "FileHashStore - retrieve_object: Request to retrieve object for pid: %s",
            pid,
        )
        if pid is None or pid.replace(" ", "") == "":
            exception_string = f"Pid cannot be None or empty, pid: {pid}"
            logging.error("FileHashStore - retrieve_object: %s", exception_string)
            raise ValueError(exception_string)

        entity = "objects"
        ab_id = self.get_sha256_hex_digest(pid)
        sysmeta_exists = self.exists(entity, ab_id)
        if sysmeta_exists:
            logging.debug(
                "FileHashStore - retrieve_object: Sysmeta exists for pid: %s, retrieving object.",
                pid,
            )
            obj_stream = self.open(entity, ab_id)
        else:
            exception_string = f"No sysmeta found for pid: {pid}"
            logging.error("FileHashStore - retrieve_object: %s", exception_string)
            raise ValueError(exception_string)
        logging.info(
            "FileHashStore - retrieve_object: Retrieved object for pid: %s", pid
        )
        return obj_stream

    def retrieve_sysmeta(self, pid):
        logging.debug(
            "FileHashStore - retrieve_sysmeta: Request to retrieve sysmeta for pid: %s",
            pid,
        )
        if pid is None or pid.replace(" ", "") == "":
            exception_string = f"Pid cannot be None or empty, pid: {pid}"
            logging.error("FileHashStore - retrieve_sysmeta: %s", exception_string)
            raise ValueError(exception_string)

        entity = "sysmeta"
        ab_id = self.get_sha256_hex_digest(pid)
        sysmeta_exists = self.exists(entity, ab_id)
        if sysmeta_exists:
            logging.debug(
                "FileHashStore - retrieve_sysmeta: Sysmeta exists for pid: %s, retrieving sysmeta.",
                pid,
            )
            ab_id = self.get_sha256_hex_digest(pid)
            s_path = self.open(entity, ab_id)
            s_content = s_path.read().decode("utf-8").split("\x00", 1)
            s_path.close()
            sysmeta = s_content[1]
        else:
            exception_string = f"No sysmeta found for pid: {pid}"
            logging.error("FileHashStore - retrieve_sysmeta: %s", exception_string)
            raise ValueError(exception_string)
        logging.info(
            "FileHashStore - retrieve_sysmeta: Retrieved sysmeta for pid: %s", pid
        )
        return sysmeta

    def delete_object(self, pid):
        logging.debug(
            "FileHashStore - delete_object: Request to delete object for pid: %s", pid
        )
        if pid is None or pid.replace(" ", "") == "":
            exception_string = f"Pid cannot be None or empty, pid: {pid}"
            logging.error("FileHashStore - delete_object: %s", exception_string)
            raise ValueError(exception_string)

        entity = "objects"
        ab_id = self.get_sha256_hex_digest(pid)
        self.delete(entity, ab_id)
        logging.info(
            "FileHashStore - delete_object: Successfully deleted object for pid: %s",
            pid,
        )
        return True

    def delete_sysmeta(self, pid):
        logging.debug(
            "FileHashStore - delete_sysmeta: Request to delete sysmeta for pid: %s",
            pid,
        )
        if pid is None or pid.replace(" ", "") == "":
            exception_string = f"Pid cannot be None or empty, pid: {pid}"
            logging.error("FileHashStore - delete_sysmeta: %s", exception_string)
            raise ValueError(exception_string)

        entity = "sysmeta"
        ab_id = self.get_sha256_hex_digest(pid)
        self.delete(entity, ab_id)
        logging.info(
            "FileHashStore - delete_sysmeta: Successfully deleted sysmeta for pid: %s",
            pid,
        )
        return True

    def get_hex_digest(self, pid, algorithm):
        logging.debug(
            "FileHashStore - get_hex_digest: Request to get hex digest for object with pid: %s",
            pid,
        )
        if pid is None or pid.replace(" ", "") == "":
            exception_string = f"Pid cannot be None or empty, pid: {pid}"
            logging.error("FileHashStore - get_hex_digest: %s", exception_string)
            raise ValueError(exception_string)
        if algorithm is None or algorithm.replace(" ", "") == "":
            exception_string = f"Algorithm cannot be None or empty, pid: {pid}"
            logging.error("FileHashStore - get_hex_digest: %s", exception_string)
            raise ValueError(exception_string)

        entity = "objects"
        algorithm = self.clean_algorithm(algorithm)
        ab_id = self.get_sha256_hex_digest(pid)
        if not self.exists(entity, ab_id):
            exception_string = f"No object found for pid: {pid}"
            logging.error("FileHashStore - get_hex_digest: %s", exception_string)
            raise ValueError(exception_string)
        c_stream = self.open(entity, ab_id)
        hex_digest = self.computehash(c_stream, algorithm=algorithm)

        logging_info_statement = (
            f"FileHashStore - get_hex_digest: Successfully calculated hex digest for pid: {pid}."
            + f" Hex Digest: {hex_digest}",
        )
        logging.info(logging_info_statement)
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

        logging.debug(
            "FileHashStore - put_object: Request to put object for pid: %s", pid
        )
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
        logging.debug(
            "FileHashStore - put_object: Successfully put object for pid: %s",
            pid,
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
            exception_string = f"File already exists for pid: {pid} at {abs_file_path}"
            logging.error(
                "FileHashStore - _move_and_get_checksums: %s", exception_string
            )
            raise FileExistsError(exception_string)

        rel_file_path = os.path.relpath(abs_file_path, self.objects)

        # Create temporary file and calculate hex digests
        debug_tmp_file_str = (
            "FileHashStore - _move_and_get_checksums: Creating temp"
            + f" file and calculating checksums for pid: {pid}"
        )
        logging.debug(debug_tmp_file_str)
        hex_digests, tmp_file_name = self._mktempfile(stream, additional_algorithm)
        logging.debug(
            "FileHashStore - _move_and_get_checksums: Temp file created: %s",
            tmp_file_name,
        )

        # Only move file if it doesn't exist.
        # Files are stored once and only once
        if not os.path.isfile(abs_file_path):
            if checksum_algorithm is not None and checksum is not None:
                hex_digest_stored = hex_digests[checksum_algorithm]
                if hex_digest_stored != checksum:
                    self.delete(entity, tmp_file_name)
                    exception_string = (
                        "Hex digest and checksum do not match - file not stored."
                        + f" Algorithm: {checksum_algorithm}."
                        + f" Checksum provided: {checksum} != Hex Digest: {hex_digest_stored}"
                    )
                    logging.error(
                        "FileHashStore - _move_and_get_checksums: %s", exception_string
                    )
                    raise ValueError(exception_string)
            is_duplicate = False
            try:
                debug_move_tmp_file_str = (
                    "FileHashStore - _move_and_get_checksums: Moving temp file to permanent"
                    + f" location: {abs_file_path}",
                )
                logging.debug(debug_move_tmp_file_str)
                shutil.move(tmp_file_name, abs_file_path)
            except Exception as err:
                # Revert storage process
                exception_string = f"Unexpected {err=}, {type(err)=}"
                logging.error(
                    "FileHashStore - _move_and_get_checksums: %s", exception_string
                )
                if os.path.isfile(abs_file_path):
                    # Check to see if object has moved successfully before deleting
                    debug_file_found_exception_str = (
                        "FileHashStore - _move_and_get_checksums: Permanent file"
                        + f" found during exception, checking hex digest for pid: {pid}"
                    )
                    logging.debug(debug_file_found_exception_str)
                    pid_checksum = self.get_hex_digest(pid, self.algorithm)
                    if pid_checksum == hex_digests.get(self.algorithm):
                        # If the checksums match, return and log warning
                        warning_file_stored_str = (
                            "FileHashStore - _move_and_get_checksums: File moved"
                            + f" successfully but unexpected issue encountered: {exception_string}",
                        )
                        logging.warning(warning_file_stored_str)
                        return
                    else:
                        debug_file_incomplete_state_str = (
                            "FileHashStore - _move_and_get_checksums: Permanent file"
                            + f" found but with incomplete state, deleting file: {abs_file_path}",
                        )
                        logging.debug(debug_file_incomplete_state_str)
                        self.delete(entity, abs_file_path)
                logging.debug(
                    "FileHashStore - _move_and_get_checksums: Deleting temporary file: %s",
                    tmp_file_name,
                )
                self.delete(entity, tmp_file_name)
                err_msg = (
                    "Aborting store_object upload - an unexpected error has occurred when moving"
                    + f" file to: {ab_id} - Error: {err}"
                )
                logging.error("FileHashStore - _move_and_get_checksums: %s", err_msg)
                raise
        else:
            # Else delete temporary file
            warning_duplicate_file_str = (
                f"FileHashStore - _move_and_get_checksums: Object exists at: {abs_file_path},"
                + " deleting temporary file."
            )
            logging.warning(warning_duplicate_file_str)
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
        algorithm_list_to_calculate = self.default_algo_list

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
            self.clean_algorithm(algorithm)
            if algorithm in self.other_algo_list:
                debug_additional_other_algo_str = (
                    f"FileHashStore - _mktempfile: additional algorithm: {algorithm} found"
                    + " in other_algo_lists, adding to list of algorithms to calculate."
                )
                logging.debug(debug_additional_other_algo_str)
                algorithm_list_to_calculate.append(algorithm)

        logging.debug(
            "FileHashStore - _mktempfile: tmp file created: %s, calculating hex digests.",
            tmp.name,
        )
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

        logging.debug("FileHashStore - _mktempfile: Hex digests calculated.")
        return hex_digest_dict, tmp.name

    def put_sysmeta(self, pid, sysmeta):
        """Store contents of `sysmeta` on disk using the hash of the given pid

        Args:
            pid (string): Authority-based identifier.
            sysmeta (mixed): String or path to sysmeta document.

        Returns:
            ab_id (string): Address of the sysmeta document.
        """
        logging.debug(
            "FileHashStore - put_sysmeta: Request to put sysmeta for pid: %s", pid
        )

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
                logging.debug(
                    "FileHashStore - put_sysmeta: Successfully put sysmeta for pid: %s",
                    pid,
                )
                return ab_id
            except Exception as err:
                exception_string = f"Unexpected {err=}, {type(err)=}"
                logging.error("FileHashStore - put_sysmeta: %s", exception_string)
                if os.path.exists(sysmeta_tmp):
                    # Remove tmp sysmeta, calling app must re-upload
                    logging.debug(
                        "FileHashStore - put_sysmeta: Deleting sysmeta for pid: %s", pid
                    )
                    self.sysmeta.delete(sysmeta_tmp)
                err_msg = f"Aborting store_sysmeta upload - an unexpected error has occurred: {err}"
                logging.error("FileHashStore - put_sysmeta: %s", err_msg)
                raise
        else:
            exception_string = (
                f"Attempt to move sysmeta for pid: {pid}"
                + f", but sysmeta temp file not found: {sysmeta_tmp}"
            )
            logging.error("FileHashStore - put_sysmeta: %s", exception_string)
            raise FileNotFoundError()

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
        logging.debug(
            "FileHashStore - _mktmpsysmeta: Writing stream to tmp sysmeta file: %s",
            tmp.name,
        )
        with tmp as tmp_file:
            tmp_file.write(namespace.encode("utf-8"))
            tmp_file.write(b"\x00")
            for data in stream:
                tmp_file.write(self._to_bytes(data))

        logging.debug(
            "FileHashStore - _mktmpsysmeta: Successfully written to tmp sysmeta file: %s",
            tmp.name,
        )
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
            exception_string = f"Algorithm not supported: {cleaned_string}"
            logging.error("FileHashStore: clean_algorithm: %s", exception_string)
            raise ValueError(exception_string)
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

    # Other Static Methods

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
