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
import fcntl
import yaml
from hashstore import HashStore, ObjectMetadata


class FileHashStore(HashStore):
    """FileHashStore is a content-addressable file manager based on Derrick
    Gilland's 'hashfs' library. It supports the storage of objects on disk using
    a content identifier to address files.

    FileHashStore initializes using a given properties dictionary containing the
    required keys (see Args). Upon initialization, FileHashStore verifies the provided
    properties and attempts to write a configuration file 'hashstore.yaml' to the given
    store path directory. Properties must always be supplied to ensure consistent
    usage of FileHashStore once configured.

    :param dict properties: A Python dictionary with the following keys (and values):
        - store_path (str): Path to the HashStore directory.
        - store_depth (int): Depth when sharding an object's hex digest.
        - store_width (int): Width of directories when sharding an object's hex digest.
        - store_algorithm (str): Hash algorithm used for calculating the object's hex digest.
        - store_metadata_namespace (str): Namespace for the HashStore's system metadata.
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
    reference_lock = threading.Lock()
    object_locked_pids = []
    metadata_locked_pids = []
    reference_locked_cids = []

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
                self._write_properties(properties)
            # Default algorithm list for FileHashStore based on config file written
            self._set_default_algorithms()
            # Complete initialization/instantiation by setting and creating store directories
            self.objects = self.root + "/objects"
            self.metadata = self.root + "/metadata"
            self.refs = self.root + "/refs"
            if not os.path.exists(self.objects):
                self._create_path(self.objects + "/tmp")
            if not os.path.exists(self.metadata):
                self._create_path(self.metadata + "/tmp")
            if not os.path.exists(self.refs):
                self._create_path(self.refs + "/tmp")
                self._create_path(self.refs + "/pid")
                self._create_path(self.refs + "/cid")
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

    @staticmethod
    def _load_properties(hahstore_yaml_path, hashstore_required_prop_keys):
        """Get and return the contents of the current HashStore configuration.

        :return: HashStore properties with the following keys (and values):
            - ``store_depth`` (int): Depth when sharding an object's hex digest.
            - ``store_width`` (int): Width of directories when sharding an object's hex digest.
            - ``store_algorithm`` (str): Hash algo used for calculating the object's hex digest.
            - ``store_metadata_namespace`` (str): Namespace for the HashStore's system metadata.
        :rtype: dict
        """
        if not os.path.exists(hahstore_yaml_path):
            exception_string = (
                "FileHashStore - load_properties: hashstore.yaml not found"
                + " in store root path."
            )
            logging.critical(exception_string)
            raise FileNotFoundError(exception_string)

        # Open file
        with open(hahstore_yaml_path, "r", encoding="utf-8") as hs_yaml_file:
            yaml_data = yaml.safe_load(hs_yaml_file)

        # Get hashstore properties
        hashstore_yaml_dict = {}
        for key in hashstore_required_prop_keys:
            if key != "store_path":
                hashstore_yaml_dict[key] = yaml_data[key]
        logging.debug(
            "FileHashStore - load_properties: Successfully retrieved 'hashstore.yaml' properties."
        )
        return hashstore_yaml_dict

    def _write_properties(self, properties):
        """Writes 'hashstore.yaml' to FileHashStore's root directory with the respective
        properties object supplied.

        :param properties: A Python dictionary with the following keys (and values):
            - ``store_depth`` (int): Depth when sharding an object's hex digest.
            - ``store_width`` (int): Width of directories when sharding an object's hex digest.
            - ``store_algorithm`` (str): Hash algo used for calculating the object's hex digest.
            - ``store_metadata_namespace`` (str): Namespace for the HashStore's system metadata.
        :type properties: dict
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
                f" cannot be used as default for HashStore. Must be one of: "
                + f"{', '.join(accepted_store_algorithms)}"
                f" which are DataONE controlled algorithm values"
            )
            logging.error(exception_string)
            raise ValueError(exception_string)

        # If given store path doesn't exist yet, create it.
        if not os.path.exists(self.root):
            self._create_path(self.root)

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
        ) as hs_yaml_file:
            hs_yaml_file.write(hashstore_configuration_yaml)

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

        :param int store_depth: Depth when sharding an object's hex digest.
        :param int store_width: Width of directories when sharding an object's hex digest.
        :param str store_algorithm: Hash algorithm used for calculating the object's hex digest.
        :param str store_metadata_namespace: Namespace for the HashStore's system metadata.

        :return: A YAML string representing the configuration for a HashStore.
        :rtype: str
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

        :param dict properties: HashStore properties.
        :param str prop_store_path: Store path to check.
        """
        if os.path.exists(self.hashstore_configuration_yaml):
            logging.debug(
                "FileHashStore - Config found (hashstore.yaml) at {%s}. Verifying properties.",
                self.hashstore_configuration_yaml,
            )
            # If 'hashstore.yaml' is found, verify given properties before init
            hashstore_yaml_dict = self._load_properties(
                self.hashstore_configuration_yaml, self.property_required_keys
            )
            for key in self.property_required_keys:
                # 'store_path' is required to init HashStore but not saved in `hashstore.yaml`
                if key != "store_path":
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

        :param dict properties: Dictionary containing filehashstore properties.

        :raises KeyError: If key is missing from the required keys.
        :raises ValueError: If value is missing for a required key.

        :return: The given properties object (that has been validated).
        :rtype: dict
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

        def lookup_algo(algo_to_translate):
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
            return dataone_algo_translation[algo_to_translate]

        if not os.path.exists(self.hashstore_configuration_yaml):
            exception_string = (
                "FileHashStore - set_default_algorithms: hashstore.yaml not found"
                + " in store root path."
            )
            logging.critical(exception_string)
            raise FileNotFoundError(exception_string)

        with open(
            self.hashstore_configuration_yaml, "r", encoding="utf-8"
        ) as hs_yaml_file:
            yaml_data = yaml.safe_load(hs_yaml_file)

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
        if pid is None and self._check_arg_data(data):
            # If no pid is supplied, store the object only without tagging
            logging.debug("FileHashStore - store_object: Request to store data only.")
            object_metadata = self._store_data_only(data)
            logging.info(
                "FileHashStore - store_object: Successfully stored object for cid: %s",
                object_metadata.cid,
            )
        else:
            # Else the object will be stored and tagged
            logging.debug(
                "FileHashStore - store_object: Request to store object for pid: %s", pid
            )
            # Validate input parameters
            self._check_string(pid, "pid", "store_object")
            self._check_arg_data(data)
            self._check_integer(expected_object_size)
            (
                additional_algorithm_checked,
                checksum_algorithm_checked,
            ) = self._check_arg_algorithms_and_checksum(
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
                object_metadata = self._store_and_validate_data(
                    pid,
                    data,
                    additional_algorithm=additional_algorithm_checked,
                    checksum=checksum,
                    checksum_algorithm=checksum_algorithm_checked,
                    file_size_to_validate=expected_object_size,
                )
                self.tag_object(pid, object_metadata.cid)
                logging.info(
                    "FileHashStore - store_object: Successfully stored object for pid: %s",
                    pid,
                )
            except Exception as err:
                exception_string = (
                    f"FileHashStore - store_object: failed to store object for pid: {pid}."
                    + f" Unexpected {err=}, {type(err)=}"
                )
                logging.error(exception_string)
                raise err
            finally:
                # Release pid
                with self.object_lock:
                    logging.debug(
                        "FileHashStore - store_object: Removing pid: %s from object_locked_pids.",
                        pid,
                    )
                    self.object_locked_pids.remove(pid)

        return object_metadata

    def verify_object(
        self, object_metadata, checksum, checksum_algorithm, expected_file_size
    ):
        self._check_string(checksum, "checksum", "verify_object")
        self._check_string(checksum_algorithm, "checksum_algorithm", "verify_object")
        self._check_integer(expected_file_size)
        if object_metadata is None or not isinstance(object_metadata, ObjectMetadata):
            exception_string = (
                "FileHashStore - verify_object: 'object_metadata' cannot be None."
                + " Must be a 'ObjectMetadata' object."
            )
            logging.error(exception_string)
            raise ValueError(exception_string)
        else:
            logging.info(
                "FileHashStore - verify_object: Called to verify object with id: %s",
                object_metadata.cid,
            )
            object_metadata_hex_digests = object_metadata.hex_digests
            object_metadata_file_size = object_metadata.obj_size
            checksum_algorithm_checked = self._clean_algorithm(checksum_algorithm)

            try:
                self._verify_object_information(
                    pid=None,
                    checksum=checksum,
                    checksum_algorithm=checksum_algorithm_checked,
                    entity="objects",
                    hex_digests=object_metadata_hex_digests,
                    tmp_file_name=None,
                    tmp_file_size=object_metadata_file_size,
                    file_size_to_validate=expected_file_size,
                )
                logging.info(
                    "FileHashStore - verify_object: object has been validated for cid: %s",
                    object_metadata.cid,
                )
                return True
            # pylint: disable=W0718
            except Exception as err:
                exception_string = (
                    f"FileHashStore - verify_object: object not valid: {err}."
                )
                logging.info(exception_string)
                return False

    def tag_object(self, pid, cid):
        logging.debug(
            "FileHashStore - tag_object: Tagging object cid: {%s} with pid: {%s}.",
            cid,
            pid,
        )
        self._check_string(pid, "pid", "tag_object")
        self._check_string(cid, "cid", "tag_object")
        # Wait for the cid to release if it's being tagged
        while cid in self.reference_locked_cids:
            logging.debug(
                "FileHashStore - tag_object: (cid) %s is currently locked. Waiting.",
                cid,
            )
            time.sleep(self.time_out_sec)
        # Modify reference_locked_cids consecutively
        with self.reference_lock:
            logging.debug(
                "FileHashStore - tag_object: Adding cid: %s to reference_locked_cids.",
                cid,
            )
            self.reference_locked_cids.append(cid)
        try:
            pid_ref_abs_path = self._resolve_path("pid", pid)
            cid_ref_abs_path = self._resolve_path("cid", cid)
            tmp_root_path = self._get_store_path("refs") / "tmp"

            # Proceed to tagging process
            if os.path.exists(pid_ref_abs_path):
                # A pid reference file can only contain one cid
                exception_string = (
                    "FileHashStore - write_pid_refs_file: pid ref file already exists for"
                    + pid_ref_abs_path
                )
                logging.error(exception_string)
                raise FileExistsError(exception_string)
            elif os.path.exists(cid_ref_abs_path):
                # Create the pid refs file
                pid_tmp_file_path = self._write_refs_file(tmp_root_path, cid, "pid")
                self._create_path(os.path.dirname(pid_ref_abs_path))
                shutil.move(pid_tmp_file_path, pid_ref_abs_path)
                # Update cid ref files as it already exists
                if not self._is_pid_in_cid_refs_file(pid, cid_ref_abs_path):
                    self._update_cid_refs(cid_ref_abs_path, pid)
                self._verify_hashstore_references(pid, cid, "update")
                logging.info(
                    "FileHashStore - tag_object: Successfully updated cid: %s with pid: %s",
                    cid,
                    pid,
                )
                return True
            else:
                # All ref files begin as tmp files and get moved sequentially at once
                # Get tmp files with the expected cid and pid refs content
                pid_tmp_file_path = self._write_refs_file(tmp_root_path, cid, "pid")
                cid_tmp_file_path = self._write_refs_file(tmp_root_path, pid, "cid")
                # Create paths for pid ref file in '.../refs/pid' and cid ref file in '.../refs/cid'
                self._create_path(os.path.dirname(pid_ref_abs_path))
                self._create_path(os.path.dirname(cid_ref_abs_path))
                # Move both files
                shutil.move(pid_tmp_file_path, pid_ref_abs_path)
                shutil.move(cid_tmp_file_path, cid_ref_abs_path)
                # Ensure that the reference files have been written as expected
                # If there is an issue, client or user will have to manually review
                self._verify_hashstore_references(pid, cid, "create")

                logging.info(
                    "FileHashStore - tag_object: Successfully tagged cid: %s with pid %s",
                    cid,
                    pid,
                )
                return True
        finally:
            # Release cid
            with self.reference_lock:
                logging.debug(
                    "FileHashStore - tag_object: Removing cid: %s from reference_locked_cids.",
                    cid,
                )
                self.reference_locked_cids.remove(cid)

    def find_object(self, pid):
        logging.debug(
            "FileHashStore - find_object: Request to find object for for pid: %s", pid
        )
        self._check_string(pid, "pid", "find_object")

        pid_ref_abs_path = self._resolve_path("pid", pid)
        if os.path.exists(pid_ref_abs_path):
            # Read the file to get the cid from the pid reference
            with open(pid_ref_abs_path, "r", encoding="utf8") as pid_ref_file:
                pid_refs_cid = pid_ref_file.read()

            # Confirm that the cid reference file exists
            cid_ref_abs_path = self._resolve_path("cid", pid_refs_cid)
            if os.path.exists(cid_ref_abs_path):
                # Check that the pid is actually found in the cid reference file
                if self._is_pid_in_cid_refs_file(pid, cid_ref_abs_path):
                    # Object must also exist in order to return the cid retrieved
                    if not self._exists("objects", pid_refs_cid):
                        err_msg = (
                            f"FileHashStore - find_object: Refs file found for pid ({pid}) at"
                            + pid_ref_abs_path
                            + f", but object referenced does not exist, cid: {pid_refs_cid}"
                        )
                        raise FileNotFoundError(err_msg)
                    else:
                        return pid_refs_cid
                else:
                    # If not, it is an orphan pid refs file
                    err_msg = (
                        "FileHashStore - find_object: pid refs file exists with cid: "
                        + pid_refs_cid
                        + f", but is missing from cid refs file: {cid_ref_abs_path}"
                    )
                    logging.error(err_msg)
                    raise ValueError(err_msg)
            else:
                err_msg = (
                    f"FileHashStore - find_object: pid refs file exists with cid: {pid_refs_cid}"
                    + f", but cid refs file not found: {cid_ref_abs_path}"
                )
                logging.error(err_msg)
                raise FileNotFoundError(err_msg)
        else:
            err_msg = (
                f"FileHashStore - find_object: pid refs file not found for pid ({pid}): "
                + pid_ref_abs_path
            )
            raise FileNotFoundError(err_msg)

    def store_metadata(self, pid, metadata, format_id=None):
        logging.debug(
            "FileHashStore - store_metadata: Request to store metadata for pid: %s", pid
        )
        # Validate input parameters
        self._check_string(pid, "pid", "store_metadata")
        checked_format_id = self._check_arg_format_id(format_id, "store_metadata")
        self._check_arg_data(metadata)

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
            metadata_cid = self._put_metadata(metadata, pid, checked_format_id)

            logging.info(
                "FileHashStore - store_metadata: Successfully stored metadata for pid: %s",
                pid,
            )
            return metadata_cid
        finally:
            # Release pid
            with self.metadata_lock:
                logging.debug(
                    "FileHashStore - store_metadata: Removing pid: %s from metadata_locked_pids.",
                    pid,
                )
                self.metadata_locked_pids.remove(pid)

    def retrieve_object(self, pid):
        logging.debug(
            "FileHashStore - retrieve_object: Request to retrieve object for pid: %s",
            pid,
        )
        self._check_string(pid, "pid", "retrieve_object")

        object_cid = self.find_object(pid)
        entity = "objects"

        if object_cid:
            logging.debug(
                "FileHashStore - retrieve_object: Metadata exists for pid: %s, retrieving object.",
                pid,
            )
            obj_stream = self._open(entity, object_cid)
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
        self._check_string(pid, "pid", "retrieve_metadata")
        checked_format_id = self._check_arg_format_id(format_id, "retrieve_metadata")

        entity = "metadata"
        metadata_directory = self._computehash(pid)
        if format_id is None:
            metadata_document_name = self._computehash(self.sysmeta_ns)
        else:
            metadata_document_name = self._computehash(checked_format_id)
        rel_path = "/".join(self._shard(metadata_directory))
        full_path_without_directory = rel_path + "/" + metadata_document_name
        metadata_exists = self._exists(entity, full_path_without_directory)

        if metadata_exists:
            metadata_stream = self._open(entity, full_path_without_directory)
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

    def delete_object(self, ab_id, id_type=None):
        logging.debug(
            "FileHashStore - delete_object: Request to delete object for id: %s", ab_id
        )
        self._check_string(ab_id, "ab_id", "delete_object")
        if id_type is "cid":
            cid_refs_abs_path = self._resolve_path("cid", ab_id)
            # If the refs file still exists, do not delete the object
            if not os.path.exists(cid_refs_abs_path):
                self._delete("objects", ab_id)
                return
        else:
            # id_type is "pid"
            pid = ab_id
            objects_to_delete = []
            rel_path = "/".join(self._shard(self._computehash(pid)))
            metadata_rel_path = self._get_store_path("metadata") / rel_path
            metadata_file_paths = self._get_file_paths(metadata_rel_path)
            # Rename paths by appending _delete to the file name
            if metadata_file_paths is not None:
                for path in metadata_file_paths:
                    objects_to_delete.append(self._rename_path_for_deletion(path))

            try:
                cid = self.find_object(pid)
            except FileNotFoundError as fnfe:
                if "pid refs file not found" in fnfe:
                    # Nothing to delete
                    return
                if "cid refs file not found" in fnfe:
                    # Delete pid refs file
                    objects_to_delete.append(
                        self._rename_path_for_deletion(self._resolve_path("pid", pid))
                    )
                    # Remove all files confirmed for deletion
                    for obj in objects_to_delete:
                        os.remove(obj)
                    return
                if "object referenced does not exist" in fnfe:
                    # Delete pid refs file
                    pid_ref_abs_path = self._resolve_path("pid", pid)
                    # Add pid refs file to delete
                    objects_to_delete.append(
                        self._rename_path_for_deletion(pid_ref_abs_path)
                    )
                    # Remove pid from cid refs file
                    # Retrieve the cid from the pid refs file
                    with open(pid_ref_abs_path, "r", encoding="utf8") as pid_ref_file:
                        pid_refs_cid = pid_ref_file.read()
                    cid_ref_abs_path = self._resolve_path("cid", pid_refs_cid)
                    # Remove if the pid refs is found
                    if self._is_pid_in_cid_refs_file(pid, cid_ref_abs_path):
                        self._delete_cid_refs_pid(cid_ref_abs_path, pid)
                    # Remove all files confirmed for deletion
                    for obj in objects_to_delete:
                        os.remove(obj)
                    self._delete("pid", pid)
                    return
            except ValueError as ve:
                if "is missing from cid refs file" in ve:
                    # Delete pid refs file
                    pid_ref_abs_path = self._resolve_path("pid", pid)
                    objects_to_delete.append(
                        self._rename_path_for_deletion(pid_ref_abs_path)
                    )
                    # Remove all files confirmed for deletion
                    for obj in objects_to_delete:
                        os.remove(obj)
                    return

            # Proceed with next steps - cid has been retrieved without any issues
            while cid in self.reference_locked_cids:
                logging.debug(
                    "FileHashStore - delete_object: (cid) %s is currently locked. Waiting",
                    cid,
                )
                time.sleep(self.time_out_sec)
            # Modify reference_locked_cids consecutively
            with self.reference_lock:
                logging.debug(
                    "FileHashStore - delete_object: Adding cid: %s to reference_locked_cids.",
                    cid,
                )
                self.reference_locked_cids.append(cid)
            try:
                cid_ref_abs_path = self._resolve_path("cid", cid)
                pid_ref_abs_path = self._resolve_path("pid", pid)
                # First delete the pid refs file immediately
                objects_to_delete.append(
                    self._rename_path_for_deletion(pid_ref_abs_path)
                )
                # Remove pid from cid reference file
                self._delete_cid_refs_pid(cid_ref_abs_path, pid)
                # Delete cid reference file and object only if the cid refs file is empty
                if os.path.getsize(cid_ref_abs_path) == 0:
                    objects_to_delete.append(
                        self._rename_path_for_deletion(cid_ref_abs_path)
                    )
                    obj_real_path = self._resolve_path("objects", cid)
                    objects_to_delete.append(
                        self._rename_path_for_deletion(obj_real_path)
                    )
                # Remove all files confirmed for deletion
                for obj in objects_to_delete:
                    os.remove(obj)

                info_string = (
                    "FileHashStore - delete_object: Successfully deleted references, metadata and"
                    + f" object associated with pid: {pid}"
                )
                logging.info(info_string)
                return

            finally:
                # Release cid
                with self.reference_lock:
                    debug_msg = (
                        "FileHashStore - delete_object:"
                        + f" Removing cid: {cid} from reference_locked_cids."
                    )
                    logging.debug(debug_msg)
                    self.reference_locked_cids.remove(cid)

    def delete_metadata(self, pid, format_id=None):
        logging.debug(
            "FileHashStore - delete_metadata: Request to delete metadata for pid: %s",
            pid,
        )
        self._check_string(pid, "pid", "delete_metadata")
        checked_format_id = self._check_arg_format_id(format_id, "delete_metadata")
        # Get the metadata directory path for the given pid
        entity = "metadata"
        metadata_directory = self._computehash(pid)
        rel_path = "/".join(self._shard(metadata_directory))
        metadata_rel_path = self._get_store_path("metadata") / rel_path
        if format_id is None:
            # Delete all metadata files
            objects_to_delete = []
            metadata_file_paths = self._get_file_paths(metadata_rel_path)
            if metadata_file_paths is not None:
                for path in metadata_file_paths:
                    objects_to_delete.append(self._rename_path_for_deletion(path))
            for obj in objects_to_delete:
                os.remove(obj)

            info_string = (
                "FileHashStore - delete_metadata: Successfully deleted all metadata for pid: %s",
                pid,
            )
            logging.info(info_string)
            return
        else:
            # Delete a specific metadata file
            metadata_document_name = self._computehash(checked_format_id)
            full_path_without_directory = rel_path + "/" + metadata_document_name
            metadata_exists = self._exists(entity, full_path_without_directory)
            if metadata_exists:
                self._delete(entity, full_path_without_directory)

            info_string = (
                "FileHashStore - delete_metadata: Successfully deleted metadata for pid:"
                + f" {pid} for format_id: {format_id}"
            )
            logging.info(info_string)
            return

    def get_hex_digest(self, pid, algorithm):
        logging.debug(
            "FileHashStore - get_hex_digest: Request to get hex digest for object with pid: %s",
            pid,
        )
        self._check_string(pid, "pid", "get_hex_digest")
        self._check_string(algorithm, "algorithm", "get_hex_digest")

        entity = "objects"
        algorithm = self._clean_algorithm(algorithm)
        object_cid = self.find_object(pid)
        if not self._exists(entity, object_cid):
            exception_string = (
                f"FileHashStore - get_hex_digest: No object found for pid: {pid}"
            )
            logging.error(exception_string)
            raise ValueError(exception_string)
        cid_stream = self._open(entity, object_cid)
        hex_digest = self._computehash(cid_stream, algorithm=algorithm)

        info_string = (
            f"FileHashStore - get_hex_digest: Successfully calculated hex digest for pid: {pid}."
            + f" Hex Digest: {hex_digest}",
        )
        logging.info(info_string)
        return hex_digest

    # FileHashStore Core Methods

    def _store_and_validate_data(
        self,
        pid,
        file,
        extension=None,
        additional_algorithm=None,
        checksum=None,
        checksum_algorithm=None,
        file_size_to_validate=None,
    ):
        """Store contents of `file` on disk, validate the object's parameters if provided,
        and tag/reference the object.

        :param str pid: Authority-based identifier.
        :param mixed file: Readable object or path to file.
        :param str extension: Optional extension to append to file when saving.
        :param str additional_algorithm: Optional algorithm value to include when returning
            hex digests.
        :param str checksum: Optional checksum to validate object against hex digest before moving
            to permanent location.
        :param str checksum_algorithm: Algorithm value of the given checksum.
        :param bytes file_size_to_validate: Expected size of the object.

        :return: ObjectMetadata - object that contains the object id, object file size,
            and hex digest dictionary.
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

        object_metadata = ObjectMetadata(
            pid, object_cid, obj_file_size, hex_digest_dict
        )
        logging.debug(
            "FileHashStore - put_object: Successfully put object for pid: %s",
            pid,
        )
        return object_metadata

    def _store_data_only(self, data):
        """Store an object to HashStore and return the ID and a hex digest
        dictionary of the default algorithms. This method does not validate the
        object and writes directly to `/objects` after the hex digests are calculated.

        :param mixed data: String or path to object.

        :raises IOError: If the object fails to store.
        :raises FileExistsError: If the file already exists.

        :return: ObjectMetadata - object that contains the object ID, object file
            size, and hex digest dictionary.
        """
        logging.debug(
            "FileHashStore - _store_data_only: Request to store data object only."
        )

        try:
            # Ensure the data is a stream
            stream = Stream(data)

            # Get the hex digest dictionary
            with closing(stream):
                (
                    object_ref_pid_location,
                    obj_file_size,
                    hex_digest_dict,
                ) = self._move_and_get_checksums(None, stream)

            object_metadata = ObjectMetadata(
                None, object_ref_pid_location, obj_file_size, hex_digest_dict
            )
            # The permanent address of the data stored is based on the data's checksum
            cid = hex_digest_dict.get(self.algorithm)
            logging.debug(
                "FileHashStore - _store_data_only: Successfully stored object with cid: %s",
                cid,
            )
            return object_metadata
        # pylint: disable=W0718
        except Exception as err:
            exception_string = (
                "FileHashStore - _store_data_only: failed to store object."
                + f" Unexpected {err=}, {type(err)=}"
            )
            logging.error(exception_string)
            raise err

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
        raise an exception. If an algorithm and checksum are provided, it will proceed to
        validate the object (and delete the tmpFile if the hex digest stored does
        not match what is provided).

        :param str pid: Authority-based identifier.
        :param io.BufferedReader stream: Object stream.
        :param str extension: Optional extension to append to the file
            when saving.
        :param str additional_algorithm: Optional algorithm value to include
            when returning hex digests.
        :param str checksum: Optional checksum to validate the object
            against hex digest before moving to the permanent location.
        :param str checksum_algorithm: Algorithm value of the given checksum.
        :param bytes file_size_to_validate: Expected size of the object.

        :return: tuple - Object ID, object file size, and hex digest dictionary.
        """
        debug_msg = (
            "FileHashStore - _move_and_get_checksums: Creating temp"
            + f" file and calculating checksums for pid: {pid}"
        )
        logging.debug(debug_msg)
        (
            hex_digests,
            tmp_file_name,
            tmp_file_size,
        ) = self._write_to_tmp_file_and_get_hex_digests(
            stream, additional_algorithm, checksum_algorithm
        )
        logging.debug(
            "FileHashStore - _move_and_get_checksums: Temp file created: %s",
            tmp_file_name,
        )

        # Objects are stored with their content identifier based on the store algorithm
        entity = "objects"
        object_cid = hex_digests.get(self.algorithm)
        abs_file_path = self._build_path(entity, object_cid, extension)

        # Only move file if it doesn't exist. We do not check before we create the tmp
        # file and calculate the hex digests because the given checksum could be incorrect.
        if not os.path.isfile(abs_file_path):
            # Files are stored once and only once
            self._verify_object_information(
                pid,
                checksum,
                checksum_algorithm,
                entity,
                hex_digests,
                tmp_file_name,
                tmp_file_size,
                file_size_to_validate,
            )
            self._create_path(os.path.dirname(abs_file_path))
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
                        exception_string = (
                            "FileHashStore - _move_and_get_checksums: File moved"
                            + f" successfully but unexpected issue encountered: {exception_string}",
                        )
                        logging.error(exception_string)
                        raise err
                    else:
                        debug_msg = (
                            "FileHashStore - _move_and_get_checksums: Permanent file"
                            + f" found but with incomplete state, deleting file: {abs_file_path}",
                        )
                        logging.debug(debug_msg)
                        self._delete(entity, abs_file_path)
                logging.debug(
                    "FileHashStore - _move_and_get_checksums: Deleting temporary file: %s",
                    tmp_file_name,
                )
                self._delete(entity, tmp_file_name)
                err_msg = (
                    "Aborting store_object upload - an unexpected error has occurred when moving"
                    + f" file to: {object_cid} - Error: {err}"
                )
                logging.error("FileHashStore - _move_and_get_checksums: %s", err_msg)
                raise
        else:
            # If the file exists, determine if the object is what the client states it to be
            try:
                self._verify_object_information(
                    pid,
                    checksum,
                    checksum_algorithm,
                    entity,
                    hex_digests,
                    tmp_file_name,
                    tmp_file_size,
                    file_size_to_validate,
                )
            except Exception as ge:
                # If any exception is thrown during validation,
                exception_string = (
                    "FileHashStore - _move_and_get_checksums: Object exists but cannot be verified"
                    + f" (validation error): {abs_file_path}, deleting temporary file. Error: {ge}"
                )
                logging.error(exception_string)
                raise FileExistsError from ge
            finally:
                # Delete the temporary file, it already exists so it is redundant
                self._delete(entity, tmp_file_name)

        return object_cid, tmp_file_size, hex_digests

    def _write_to_tmp_file_and_get_hex_digests(
        self, stream, additional_algorithm=None, checksum_algorithm=None
    ):
        """Create a named temporary file from a `Stream` object and return its filename
        and a dictionary of its algorithms and hex digests. If an additional and/or checksum
        algorithm is provided, it will add the respective hex digest to the dictionary if
        it is supported.

        :param io.BufferedReader stream: Object stream.
        :param str additional_algorithm: Algorithm of additional hex digest to generate.
        :param str checksum_algorithm: Algorithm of additional checksum algo to generate.

        :return: tuple - hex_digest_dict, tmp.name
            - hex_digest_dict (dict): Algorithms and their hex digests.
            - tmp.name (str): Name of the temporary file created and written into.
        """
        # Review additional hash object to digest and create new list
        algorithm_list_to_calculate = self._refine_algorithm_list(
            additional_algorithm, checksum_algorithm
        )
        tmp_root_path = self._get_store_path("objects") / "tmp"
        tmp = self._mktmpfile(tmp_root_path)

        logging.debug(
            "FileHashStore - _write_to_tmp_file_and_get_hex_digests: tmp file created:"
            + " %s, calculating hex digests.",
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
                    tmp_file.write(self._cast_to_bytes(data))
                    for hash_algorithm in hash_algorithms:
                        hash_algorithm.update(self._cast_to_bytes(data))

            logging.debug(
                "FileHashStore - _write_to_tmp_file_and_get_hex_digests: Object stream"
                + " successfully written to tmp file: %s",
                tmp.name,
            )

            hex_digest_list = [
                hash_algorithm.hexdigest() for hash_algorithm in hash_algorithms
            ]
            hex_digest_dict = dict(zip(algorithm_list_to_calculate, hex_digest_list))
            tmp_file_size = os.path.getsize(tmp.name)
            # Ready for validation and atomic move
            tmp_file_completion_flag = True

            logging.debug(
                "FileHashStore - _write_to_tmp_file_and_get_hex_digests: Hex digests calculated."
            )
            return hex_digest_dict, tmp.name, tmp_file_size
        # pylint: disable=W0718
        except Exception as err:
            exception_string = (
                "FileHashStore - _write_to_tmp_file_and_get_hex_digests:"
                + f" Unexpected {err=}, {type(err)=}"
            )
            logging.error(exception_string)
            # pylint: disable=W0707,W0719
            raise Exception(exception_string)
        except KeyboardInterrupt:
            exception_string = (
                "FileHashStore - _write_to_tmp_file_and_get_hex_digests:"
                + " Keyboard interruption by user."
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
                        "FileHashStore - _write_to_tmp_file_and_get_hex_digests:"
                        + f"Unexpected {err=} while attempting to"
                        + f" delete tmp file: {tmp.name}, {type(err)=}"
                    )
                    logging.error(exception_string)

    def _mktmpfile(self, path):
        """Create a temporary file at the given path ready to be written.

        :param str path: Path to the file location.

        :return: file object - object with a file-like interface.
        """
        # Physically create directory if it doesn't exist
        if os.path.exists(path) is False:
            self._create_path(path)

        tmp = NamedTemporaryFile(dir=path, delete=False)

        # Delete tmp file if python interpreter crashes or thread is interrupted
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
        return tmp

    # TODO: Clean up refs file methods, a lot of redundant code

    def _write_refs_file(self, path, ref_id, ref_type):
        """Write a reference file in the supplied path into a temporary file.
        All `pid` or `cid` reference files begin with a single identifier, with the
        primary difference being that a cid reference file can contain multiple lines
        of `pid`s that reference the `cid`.

        :param str path: Directory to write the temporary file
        :param str ref_id: Authority-based, persistent or content identifier

        :return: tmp_file_path - Path to the tmp refs file
        :rtype: string
        """
        logging.debug(
            "FileHashStore - write_cid_refs_file: Writing id (%s) into file: %s",
            ref_id,
            path,
        )
        try:
            with self._mktmpfile(path) as tmp_file:
                tmp_file_path = tmp_file.name
                with open(tmp_file_path, "w", encoding="utf8") as tmp_cid_ref_file:
                    if ref_type is "cid":
                        tmp_cid_ref_file.write(ref_id + "\n")
                    if ref_type is "pid":
                        tmp_cid_ref_file.write(ref_id)
                    return tmp_file_path

        except Exception as err:
            exception_string = (
                "FileHashStore - _write_refs_file: failed to write cid refs file for pid:"
                + f" {ref_id} into path: {path}. Unexpected {err=}, {type(err)=}"
            )
            logging.error(exception_string)
            raise err

    def _is_pid_in_cid_refs_file(self, pid, cid_ref_abs_path):
        """Check a cid reference file for a pid.

        :param str pid: Authority-based or persistent identifier of the object.
        :param str cid_ref_abs_path: Path to the cid refs file

        :return: pid_found
        :rtype: boolean
        """
        with open(cid_ref_abs_path, "r", encoding="utf8") as cid_ref_file:
            # Confirm that pid is not currently already tagged
            for line in cid_ref_file:
                value = line.strip()
                if pid == value:
                    return True
        return False

    @staticmethod
    def _update_cid_refs(cid_ref_abs_path, pid):
        """Update an existing CID reference file with the given PID.

        :param str cid_ref_abs_path: Absolute path to the CID reference file.
        :param str pid: Authority-based or persistent identifier of the object.
        """
        logging.debug(
            "FileHashStore - update_cid_refs: Adding pid (%s) into cid reference file: %s",
            pid,
            cid_ref_abs_path,
        )
        if not os.path.exists(cid_ref_abs_path):
            exception_string = (
                f"FileHashStore - update_cid_refs: {cid_ref_abs_path} does not exist."
                + f" Cannot write pid: {[pid]}"
            )
            logging.error(exception_string)
            raise FileNotFoundError(exception_string)

        try:
            with open(cid_ref_abs_path, "a", encoding="utf8") as cid_ref_file:
                # Lock file for the shortest amount of time possible
                file_descriptor = cid_ref_file.fileno()
                fcntl.flock(file_descriptor, fcntl.LOCK_EX)
                cid_ref_file.write(pid + "\n")
                # The context manager will take care of releasing the lock
                # But the code to explicitly release the lock if desired is below
                # fcntl.flock(f, fcntl.LOCK_UN)
        except Exception as err:
            exception_string = (
                "FileHashStore - update_cid_refs: failed to update reference for cid:"
                + f" {cid_ref_abs_path} for pid: {pid}. Unexpected {err=}, {type(err)=}"
            )
            logging.error(exception_string)
            raise err

    @staticmethod
    def _delete_cid_refs_pid(cid_ref_abs_path, pid):
        """Delete a PID from a CID reference file.

        :param str cid_ref_abs_path: Absolute path to the CID reference file.
        :param str pid: Authority-based or persistent identifier of the object.
        """
        logging.debug(
            "FileHashStore - _delete_cid_refs_pid: Deleting pid (%s) from cid reference file: %s",
            pid,
            cid_ref_abs_path,
        )
        try:
            with open(cid_ref_abs_path, "r+", encoding="utf8") as cid_ref_file:
                # Lock file immediately, this process needs to complete
                # before any others read/modify the content of cid_ref_file
                file_descriptor = cid_ref_file.fileno()
                fcntl.flock(file_descriptor, fcntl.LOCK_EX)
                new_pid_lines = [
                    cid_pid_line
                    for cid_pid_line in cid_ref_file.readlines()
                    if cid_pid_line.strip() != pid
                ]
                cid_ref_file.seek(0)
                cid_ref_file.writelines(new_pid_lines)
                cid_ref_file.truncate()
                # The context manager will take care of releasing the lock
                # But the code to explicitly release the lock if desired is below
                # fcntl.flock(f, fcntl.LOCK_UN)
        except Exception as err:
            exception_string = (
                "FileHashStore - _delete_cid_refs_pid: failed to remove pid from cid refs file:"
                + f" {cid_ref_abs_path} for pid: {pid}. Unexpected {err=}, {type(err)=}"
            )
            logging.error(exception_string)
            raise err

    def _delete_pid_refs_file(self, pid_ref_abs_path):
        """Delete a PID reference file.

        :param str pid_ref_abs_path: Absolute path to the PID reference file.
        """
        logging.debug(
            "FileHashStore - _delete_pid_refs_file: Deleting reference file: %s",
            pid_ref_abs_path,
        )

        try:
            if not os.path.exists(pid_ref_abs_path):
                err_msg = (
                    "FileHashStore - _delete_pid_refs_file: pid reference file not found: %s",
                    pid_ref_abs_path,
                )
                raise FileNotFoundError(err_msg)
            else:
                self._delete("pid", pid_ref_abs_path)

        except Exception as err:
            exception_string = (
                "FileHashStore - _delete_pid_refs_file: failed to delete pid refs file:"
                + f" {pid_ref_abs_path}. Unexpected {err=}, {type(err)=}"
            )
            logging.error(exception_string)
            raise err

    def _put_metadata(self, metadata, pid, format_id):
        """Store contents of metadata to `[self.root]/metadata` using the hash of the
        given PID and format ID as the permanent address.

        :param str pid: Authority-based identifier.
        :param str format_id: Metadata format.
        :param mixed metadata: String or path to metadata document.

        :return: Address of the metadata document.
        :rtype: str
        """
        logging.debug(
            "FileHashStore - _put_metadata: Request to put metadata for pid: %s", pid
        )
        # Create metadata tmp file and write to it
        metadata_stream = Stream(metadata)
        with closing(metadata_stream):
            metadata_tmp = self._mktmpmetadata(metadata_stream)

        # Get target and related paths (permanent location)
        metadata_directory = self._computehash(pid)
        metadata_document_name = self._computehash(format_id)
        rel_path = "/".join(self._shard(metadata_directory))
        full_path = self._get_store_path("metadata") / rel_path / metadata_document_name

        # Move metadata to target path
        if os.path.exists(metadata_tmp):
            try:
                parent = full_path.parent
                parent.mkdir(parents=True, exist_ok=True)
                # Metadata will be replaced if it exists
                shutil.move(metadata_tmp, full_path)
                logging.debug(
                    "FileHashStore - _put_metadata: Successfully put metadata for pid: %s",
                    pid,
                )
                return full_path
            except Exception as err:
                exception_string = (
                    f"FileHashStore - _put_metadata: Unexpected {err=}, {type(err)=}"
                )
                logging.error(exception_string)
                if os.path.exists(metadata_tmp):
                    # Remove tmp metadata, calling app must re-upload
                    logging.debug(
                        "FileHashStore - _put_metadata: Deleting metadata for pid: %s",
                        pid,
                    )
                    self.metadata.delete(metadata_tmp)
                raise
        else:
            exception_string = (
                f"FileHashStore - _put_metadata: Attempt to move metadata for pid: {pid}"
                + f", but metadata temp file not found: {metadata_tmp}"
            )
            logging.error(exception_string)
            raise FileNotFoundError(exception_string)

    def _mktmpmetadata(self, stream):
        """Create a named temporary file with `stream` (metadata).

        :param io.BufferedReader stream: Metadata stream.

        :return: Path/name of temporary file created and written into.
        :rtype: str
        """
        # Create temporary file in .../{store_path}/tmp
        tmp_root_path = self._get_store_path("metadata") / "tmp"
        tmp = self._mktmpfile(tmp_root_path)

        # tmp is a file-like object that is already opened for writing by default
        logging.debug(
            "FileHashStore - _mktmpmetadata: Writing stream to tmp metadata file: %s",
            tmp.name,
        )
        with tmp as tmp_file:
            for data in stream:
                tmp_file.write(self._cast_to_bytes(data))

        logging.debug(
            "FileHashStore - _mktmpmetadata: Successfully written to tmp metadata file: %s",
            tmp.name,
        )
        return tmp.name

    # FileHashStore Utility & Supporting Methods

    def _verify_object_information(
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
        """Evaluates an object's integrity - if there is a mismatch, deletes the object
        in question and raises an exception.

        :param str pid: For logging purposes.
        :param str checksum: Value of the checksum to check.
        :param str checksum_algorithm: Algorithm of the checksum.
        :param str entity: Type of object ('objects' or 'metadata').
        :param dict hex_digests: Dictionary of hex digests to parse.
        :param str tmp_file_name: Name of the temporary file.
        :param int tmp_file_size: Size of the temporary file.
        :param int file_size_to_validate: Expected size of the object.
        """
        if file_size_to_validate is not None and file_size_to_validate > 0:
            if file_size_to_validate != tmp_file_size:
                exception_string = (
                    "FileHashStore - _validate_arg_object: Object file size calculated: "
                    + f" {tmp_file_size} does not match with expected size:"
                    + f" {file_size_to_validate}."
                )
                if pid is not None:
                    self._delete(entity, tmp_file_name)
                    exception_string_for_pid = (
                        exception_string
                        + f" Tmp file deleted and file not stored for pid: {pid}"
                    )
                    logging.error(exception_string_for_pid)
                    raise ValueError(exception_string_for_pid)
                else:
                    logging.error(exception_string)
                    raise ValueError(exception_string)
        if checksum_algorithm is not None and checksum is not None:
            if checksum_algorithm not in hex_digests:
                exception_string = (
                    "FileHashStore - _validate_arg_object: checksum_algorithm"
                    + f" ({checksum_algorithm}) cannot be found in the hex digests dictionary."
                )
                logging.error(exception_string)
                raise KeyError(exception_string)
            else:
                hex_digest_stored = hex_digests[checksum_algorithm]
                if hex_digest_stored != checksum.lower():
                    exception_string = (
                        "FileHashStore - _validate_arg_object: Hex digest and checksum"
                        + f" do not match - file not stored for pid: {pid}. Algorithm:"
                        + f" {checksum_algorithm}. Checksum provided: {checksum} !="
                        + f" HexDigest: {hex_digest_stored}."
                    )
                    if pid is not None:
                        # Delete the tmp file
                        self._delete(entity, tmp_file_name)
                        exception_string_for_pid = (
                            exception_string + f" Tmp file ({tmp_file_name}) deleted."
                        )
                        logging.error(exception_string_for_pid)
                        raise ValueError(exception_string_for_pid)
                    else:
                        # Delete the object
                        cid = hex_digests[self.algorithm]
                        cid_abs_path = self._resolve_path("cid", cid)
                        self._delete(entity, cid_abs_path)
                        logging.error(exception_string)
                        raise ValueError(exception_string)

    def _verify_hashstore_references(self, pid, cid, verify_type):
        """Verifies that the supplied pid and pid reference file and content have been
        written successfully.

        :param str pid: Authority-based or persistent identifier.
        :param str cid: Content identifier.
        :param str verify_type: "update" or "create"
        """
        # Check that reference files were created
        pid_ref_abs_path = self._resolve_path("pid", pid)
        cid_ref_abs_path = self._resolve_path("cid", cid)
        if not os.path.exists(pid_ref_abs_path):
            exception_string = (
                "FileHashStore - _verify_hashstore_references: Pid refs file missing: "
                + pid_ref_abs_path
                + f" . Verify type {verify_type}"
            )
            logging.error(exception_string)
            raise FileNotFoundError(exception_string)
        if not os.path.exists(cid_ref_abs_path):
            exception_string = (
                "FileHashStore - _verify_hashstore_references: Cid refs file missing: "
                + cid_ref_abs_path
                + f" . Verify type {verify_type}"
            )
            logging.error(exception_string)
            raise FileNotFoundError(exception_string)
        # Check the content of the reference files
        # Start with the cid
        with open(pid_ref_abs_path, "r", encoding="utf8") as f:
            retrieved_cid = f.read()
        if retrieved_cid != cid:
            exception_string = (
                "FileHashStore - _verify_hashstore_references: Pid refs file exists"
                + f" ({pid_ref_abs_path}) but cid ({cid}) does not match."
                + f"Verify type {verify_type}"
            )
            logging.error(exception_string)
            raise ValueError(exception_string)
        # Then the pid
        pid_found = self._is_pid_in_cid_refs_file(pid, cid_ref_abs_path)
        if not pid_found:
            exception_string = (
                "FileHashStore - _verify_hashstore_references: Cid refs file exists"
                + f" ({cid_ref_abs_path}) but pid ({pid}) not found."
                + f" Verify type {verify_type}"
            )
            logging.error(exception_string)
            raise ValueError(exception_string)

    @staticmethod
    def _check_arg_data(data):
        """Checks a data argument to ensure that it is either a string, path, or stream
        object.

        :param data: Object to validate (string, path, or stream).
        :type data: str, os.PathLike, io.BufferedReader

        :return: True if valid.
        :rtype: bool
        """
        if (
            not isinstance(data, str)
            and not isinstance(data, Path)
            and not isinstance(data, io.BufferedIOBase)
        ):
            exception_string = (
                "FileHashStore - _validate_arg_data: Data must be a path, string or buffered"
                + f" stream type. Data type supplied: {type(data)}"
            )
            logging.error(exception_string)
            raise TypeError(exception_string)
        if isinstance(data, str):
            if data.strip() == "":
                exception_string = (
                    "FileHashStore - _validate_arg_data: Data string cannot be empty."
                )
                logging.error(exception_string)
                raise TypeError(exception_string)
        return True

    def _check_arg_algorithms_and_checksum(
        self, additional_algorithm, checksum, checksum_algorithm
    ):
        """Determines whether the caller has supplied the necessary arguments to validate
        an object with a checksum value.

        :param additional_algorithm: Value of the additional algorithm to calculate.
        :type additional_algorithm: str or None
        :param checksum: Value of the checksum.
        :type checksum: str or None
        :param checksum_algorithm: Algorithm of the checksum.
        :type checksum_algorithm: str or None

        :return: Hashlib-compatible string or 'None' for additional_algorithm and
            checksum_algorithm.
        :rtype: str
        """
        additional_algorithm_checked = None
        if additional_algorithm != self.algorithm and additional_algorithm is not None:
            # Set additional_algorithm
            additional_algorithm_checked = self._clean_algorithm(additional_algorithm)
        checksum_algorithm_checked = None
        if checksum is not None:
            self._check_string(
                checksum_algorithm,
                "checksum_algorithm",
                "_check_arg_algorithms_and_checksum (store_object)",
            )
        if checksum_algorithm is not None:
            self._check_string(
                checksum,
                "checksum",
                "_check_arg_algorithms_and_checksum (store_object)",
            )
            # Set checksum_algorithm
            checksum_algorithm_checked = self._clean_algorithm(checksum_algorithm)
        return additional_algorithm_checked, checksum_algorithm_checked

    def _check_arg_format_id(self, format_id, method):
        """Determines the metadata namespace (format_id) to use for storing,
        retrieving, and deleting metadata.

        :param str format_id: Metadata namespace to review.
        :param str method: Calling method for logging purposes.

        :return: Valid metadata namespace.
        :rtype: str
        """
        checked_format_id = None
        if format_id and not format_id.strip():
            exception_string = f"FileHashStore - {method}: Format_id cannot be empty."
            logging.error(exception_string)
            raise ValueError(exception_string)
        elif format_id is None:
            # Use default value set by hashstore config
            checked_format_id = self.sysmeta_ns
        else:
            checked_format_id = format_id
        return checked_format_id

    def _refine_algorithm_list(self, additional_algorithm, checksum_algorithm):
        """Create the final list of hash algorithms to calculate.

        :param str additional_algorithm: Additional algorithm.
        :param str checksum_algorithm: Checksum algorithm.

        :return: De-duplicated list of hash algorithms.
        :rtype: set
        """
        algorithm_list_to_calculate = self.default_algo_list
        if checksum_algorithm is not None:
            self._clean_algorithm(checksum_algorithm)
            if checksum_algorithm in self.other_algo_list:
                debug_additional_other_algo_str = (
                    f"FileHashStore - _refine_algorithm_list: checksum algo: {checksum_algorithm}"
                    + " found in other_algo_lists, adding to list of algorithms to calculate."
                )
                logging.debug(debug_additional_other_algo_str)
                algorithm_list_to_calculate.append(checksum_algorithm)
        if additional_algorithm is not None:
            self._clean_algorithm(additional_algorithm)
            if additional_algorithm in self.other_algo_list:
                debug_additional_other_algo_str = (
                    f"FileHashStore - _refine_algorithm_list: addit algo: {additional_algorithm}"
                    + " found in other_algo_lists, adding to list of algorithms to calculate."
                )
                logging.debug(debug_additional_other_algo_str)
                algorithm_list_to_calculate.append(additional_algorithm)

        # Remove duplicates
        algorithm_list_to_calculate = set(algorithm_list_to_calculate)
        return algorithm_list_to_calculate

    def _clean_algorithm(self, algorithm_string):
        """Format a string and ensure that it is supported and compatible with
        the Python `hashlib` library.

        :param str algorithm_string: Algorithm to validate.

        :return: `hashlib` supported algorithm string.
        :rtype: str
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
                "FileHashStore: _clean_algorithm: Algorithm not supported:"
                + cleaned_string
            )
            logging.error(exception_string)
            raise ValueError(exception_string)
        return cleaned_string

    def _computehash(self, stream, algorithm=None):
        """Compute the hash of a file-like object (or string) using the store algorithm by
        default or with an optional supported algorithm.

        :param mixed stream: A buffered stream (`io.BufferedReader`) of an object. A string is
            also acceptable as they are a sequence of characters (Python only).
        :param str algorithm: Algorithm of hex digest to generate.

        :return: Hex digest.
        :rtype: str
        """
        if algorithm is None:
            hashobj = hashlib.new(self.algorithm)
        else:
            check_algorithm = self._clean_algorithm(algorithm)
            hashobj = hashlib.new(check_algorithm)
        for data in stream:
            hashobj.update(self._cast_to_bytes(data))
        hex_digest = hashobj.hexdigest()
        return hex_digest

    def _exists(self, entity, file):
        """Check whether a given file id or path exists on disk.

        :param str entity: Desired entity type (e.g., "objects", "metadata").
        :param str file: The name of the file to check.

        :return: True if the file exists.
        :rtype: bool
        """
        file_exists = bool(self._resolve_path(entity, file))
        return file_exists

    def _shard(self, digest):
        """Generates a list given a digest of `self.depth` number of tokens with width
        `self.width` from the first part of the digest plus the remainder.

        Example:
            ['0d', '55', '5e', 'd77052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e']

        :param str digest: The string to be divided into tokens.

        :return: A list containing the tokens of fixed width.
        :rtype: list
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

    def _open(self, entity, file, mode="rb"):
        """Return open buffer object from given id or path. Caller is responsible
        for closing the stream.

        :param str entity: Desired entity type (ex. "objects", "metadata").
        :param str file: Address ID or path of file.
        :param str mode: Mode to open file in. Defaults to 'rb'.

        :return: An `io` stream dependent on the `mode`.
        :rtype: io.BufferedReader
        """
        realpath = self._resolve_path(entity, file)
        if realpath is None:
            raise IOError(f"Could not locate file: {file}")

        # pylint: disable=W1514
        # mode defaults to "rb"
        buffer = io.open(realpath, mode)
        return buffer

    def _delete(self, entity, file):
        """Delete file using id or path. Remove any empty directories after
        deleting. No exception is raised if file doesn't exist.

        :param str entity: Desired entity type (ex. "objects", "metadata").
        :param str file: Address ID or path of file.
        """
        realpath = self._resolve_path(entity, file)
        if realpath is None:
            return None

        try:
            os.remove(realpath)
        except OSError as err:
            exception_string = (
                f"FileHashStore - delete(): Unexpected {err=}, {type(err)=}"
            )
            logging.error(exception_string)
            raise err

    @staticmethod
    def _rename_path_for_deletion(path):
        """Move and rename a given path by appending '_delete' to the file name

        :param Path path: Path to file to rename

        :return: Path to the renamed file
        :rtype: str
        """
        if isinstance(path, str):
            path = Path(path)
        delete_path = path.with_name(path.stem + "_delete" + path.suffix)
        shutil.move(path, delete_path)
        return delete_path

    def _remove_empty(self, subpath):
        """Successively remove all empty folders starting with `subpath` and
        proceeding "up" through directory tree until reaching the `root`
        folder.

        :param str subpath: Name of directory.
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

        :param str path: Name of path.

        :return: `True` if subdirectory.
        :rtype: bool
        """
        # Append os.sep so that paths like /usr/var2/log doesn't match /usr/var.
        root_path = os.path.realpath(self.root) + os.sep
        subpath = os.path.realpath(path)
        is_subdir = subpath.startswith(root_path)
        return is_subdir

    def _create_path(self, path):
        """Physically create the folder path (and all intermediate ones) on disk.

        :param str path: The path to create.
        :raises AssertionError: If the path already exists but is not a directory.
        """
        try:
            os.makedirs(path, self.dmode)
        except FileExistsError:
            assert os.path.isdir(path), f"expected {path} to be a directory"

    def _build_path(self, entity, hash_id, extension=""):
        """Build the absolute file path for a given hash ID with an optional file extension.

        :param str entity: Desired entity type (ex. "objects", "metadata").
        :param str hash_id: A hash ID to build a file path for.
        :param str extension: An optional file extension to append to the file path.

        :return: An absolute file path for the specified hash ID.
        :rtype: str
        """
        paths = self._shard(hash_id)
        root_dir = self._get_store_path(entity)

        if extension and not extension.startswith(os.extsep):
            extension = os.extsep + extension
        elif not extension:
            extension = ""

        absolute_path = os.path.join(root_dir, *paths) + extension
        return absolute_path

    def _resolve_path(self, entity, file):
        """Attempt to determine the absolute path of a file ID or path through
        successive checking of candidate paths - first by checking whether the 'file'
        exists, followed by checking the entity type with respect to the file.

        :param str entity: Desired entity type ("objects", "metadata", "cid", "pid"),
            where "cid" & "pid" represents resolving the path to the refs files.
        :param str file: Name of the file.

        :return: Path to file
        :rtype: str
        """
        # Check for absolute path.
        if os.path.isfile(file):
            return file

        # Check for relative path.
        rel_root = ""
        if entity == "objects":
            rel_root = self.objects
        if entity == "metadata":
            rel_root = self.metadata
        relpath = os.path.join(rel_root, file)
        if os.path.isfile(relpath):
            return relpath

        # Check for sharded path.
        if entity == "cid":
            # Note, we skip checking whether the file exists for refs
            cid_ref_file_abs_path = self._build_path(entity, file)
            return cid_ref_file_abs_path
        elif entity == "pid":
            # Note, we skip checking whether the file exists for refs
            hash_id = self._computehash(file, self.algorithm)
            pid_ref_file_abs_path = self._build_path(entity, hash_id)
            return pid_ref_file_abs_path
        else:
            abspath = self._build_path(entity, file)
            if os.path.isfile(abspath):
                return abspath

    def _get_store_path(self, entity):
        """Return a path object of the root directory of the store.

        :param str entity: Desired entity type: "objects" or "metadata"

        :return: Path to requested store entity type
        :rtype: Path
        """
        if entity == "objects":
            return Path(self.objects)
        elif entity == "metadata":
            return Path(self.metadata)
        elif entity == "refs":
            return Path(self.refs)
        elif entity == "cid":
            return Path(self.refs) / "cid"
        elif entity == "pid":
            return Path(self.refs) / "pid"
        else:
            raise ValueError(
                f"entity: {entity} does not exist. Do you mean 'objects', 'metadata' or 'refs'?"
            )

    @staticmethod
    def _get_file_paths(directory):
        """Get the file paths of a given directory if it exists

        :param mixed directory: String or path to directory.

        :raises FileNotFoundError: If the directory doesn't exist

        :return: file_paths - File paths of the given directory or None if directory doesn't exist
        :rtype: List
        """
        if os.path.exists(directory):
            files = os.listdir(directory)
            file_paths = [
                directory / file for file in files if os.path.isfile(directory / file)
            ]
            return file_paths
        else:
            return None

    def _count(self, entity):
        """Return the count of the number of files in the `root` directory.

        :param str entity: Desired entity type (ex. "objects", "metadata").

        :return: Number of files in the directory.
        :rtype: int
        """
        count = 0
        directory_to_count = ""
        if entity == "objects":
            directory_to_count = self.objects
        elif entity == "metadata":
            directory_to_count = self.metadata
        elif entity == "pid":
            directory_to_count = self.refs + "/pid"
        elif entity == "cid":
            directory_to_count = self.refs + "/cid"
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
    def _check_integer(file_size):
        """Check whether a given argument is an integer and greater than 0;
        throw an exception if not.

        :param int file_size: File size to check.
        """
        if file_size is not None:
            if not isinstance(file_size, int):
                exception_string = (
                    "FileHashStore - _check_integer: size given must be an integer."
                    + f" File size: {file_size}. Arg Type: {type(file_size)}."
                )
                logging.error(exception_string)
                raise TypeError(exception_string)
            if file_size < 1:
                exception_string = (
                    "FileHashStore - _check_integer: size given must be > 0"
                )
                logging.error(exception_string)
                raise ValueError(exception_string)

    @staticmethod
    def _check_string(string, arg, method):
        """Check whether a string is None or empty; throw an exception if so.

        :param str string: Value to check.
        :param str arg: Name of the argument to check.
        :param str method: Calling method for logging purposes.
        """
        if string is None or string.strip() == "":
            exception_string = (
                f"FileHashStore - {method}: {arg} cannot be None"
                + f" or empty, {arg}: {string}."
            )
            logging.error(exception_string)
            raise ValueError(exception_string)

    @staticmethod
    def _cast_to_bytes(text):
        """Convert text to a sequence of bytes using utf-8 encoding.

        :param str text: String to convert.
        :return: Bytes with utf-8 encoding.
        :rtype: bytes
        """
        if not isinstance(text, bytes):
            text = bytes(text, "utf8")
        return text


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
