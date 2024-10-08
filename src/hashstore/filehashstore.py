"""Core module for FileHashStore"""

import atexit
import io
import multiprocessing
import shutil
import threading
import hashlib
import os
import logging
import inspect
import fcntl
import yaml
from typing import List, Dict, Union, Optional, IO, Tuple, Set, Any
from dataclasses import dataclass
from pathlib import Path
from contextlib import closing
from tempfile import NamedTemporaryFile
from hashstore import HashStore
from hashstore.filehashstore_exceptions import (
    CidRefsContentError,
    OrphanPidRefsFileFound,
    CidRefsFileNotFound,
    HashStoreRefsAlreadyExists,
    NonMatchingChecksum,
    NonMatchingObjSize,
    PidRefsAlreadyExistsError,
    PidNotFoundInCidRefsFile,
    PidRefsContentError,
    PidRefsDoesNotExist,
    PidRefsFileNotFound,
    RefsFileExistsButCidObjMissing,
    UnsupportedAlgorithm,
    StoreObjectForPidAlreadyInProgress,
    IdentifierNotLocked,
)


class FileHashStore(HashStore):
    """FileHashStore is an object storage system that was extended from Derrick Gilland's
    'hashfs' library. It supports the storage of objects on disk using a content identifier
    to address files (data objects are de-duplicated) and provides a content identifier-based
    API to interact with a HashStore.

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
    f_mode = 0o664
    d_mode = 0o755
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

    def __init__(self, properties=None):
        self.fhs_logger = logging.getLogger(__name__)
        # Now check properties
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
            self.hashstore_configuration_yaml = Path(prop_store_path) / "hashstore.yaml"
            self._verify_hashstore_properties(properties, prop_store_path)

            # If no exceptions thrown, FileHashStore ready for initialization
            self.fhs_logger.debug("Initializing, properties verified.")
            self.root = Path(prop_store_path)
            self.depth = prop_store_depth
            self.width = prop_store_width
            self.sysmeta_ns = prop_store_metadata_namespace
            # Write 'hashstore.yaml' to store path
            if not os.path.isfile(self.hashstore_configuration_yaml):
                # pylint: disable=W1201
                self.fhs_logger.debug(
                    "HashStore does not exist & configuration file not found."
                    + " Writing configuration file."
                )
                self._write_properties(properties)
            # Default algorithm list for FileHashStore based on config file written
            self._set_default_algorithms()
            # Complete initialization/instantiation by setting and creating store directories
            self.objects = self.root / "objects"
            self.metadata = self.root / "metadata"
            self.refs = self.root / "refs"
            self.cids = self.refs / "cids"
            self.pids = self.refs / "pids"
            if not os.path.exists(self.objects):
                self._create_path(self.objects / "tmp")
            if not os.path.exists(self.metadata):
                self._create_path(self.metadata / "tmp")
            if not os.path.exists(self.refs):
                self._create_path(self.refs / "tmp")
                self._create_path(self.refs / "pids")
                self._create_path(self.refs / "cids")

            # Variables to orchestrate parallelization
            # Check to see whether a multiprocessing or threading sync lock should be used
            self.use_multiprocessing = (
                os.getenv("USE_MULTIPROCESSING", "False") == "True"
            )
            if self.use_multiprocessing == "True":
                # Create multiprocessing synchronization variables
                # Synchronization values for object locked pids
                self.object_pid_lock_mp = multiprocessing.Lock()
                self.object_pid_condition_mp = multiprocessing.Condition(
                    self.object_pid_lock_mp
                )
                self.object_locked_pids_mp = multiprocessing.Manager().list()
                # Synchronization values for object locked cids
                self.object_cid_lock_mp = multiprocessing.Lock()
                self.object_cid_condition_mp = multiprocessing.Condition(
                    self.object_cid_lock_mp
                )
                self.object_locked_cids_mp = multiprocessing.Manager().list()
                # Synchronization values for metadata locked documents
                self.metadata_lock_mp = multiprocessing.Lock()
                self.metadata_condition_mp = multiprocessing.Condition(
                    self.metadata_lock_mp
                )
                self.metadata_locked_docs_mp = multiprocessing.Manager().list()
                # Synchronization values for reference locked pids
                self.reference_pid_lock_mp = multiprocessing.Lock()
                self.reference_pid_condition_mp = multiprocessing.Condition(
                    self.reference_pid_lock_mp
                )
                self.reference_locked_pids_mp = multiprocessing.Manager().list()
            else:
                # Create threading synchronization variables
                # Synchronization values for object locked pids
                self.object_pid_lock_th = threading.Lock()
                self.object_pid_condition_th = threading.Condition(
                    self.object_pid_lock_th
                )
                self.object_locked_pids_th = []
                # Synchronization values for object locked cids
                self.object_cid_lock_th = threading.Lock()
                self.object_cid_condition_th = threading.Condition(
                    self.object_cid_lock_th
                )
                self.object_locked_cids_th = []
                # Synchronization values for metadata locked documents
                self.metadata_lock_th = threading.Lock()
                self.metadata_condition_th = threading.Condition(self.metadata_lock_th)
                self.metadata_locked_docs_th = []
                # Synchronization values for reference locked pids
                self.reference_pid_lock_th = threading.Lock()
                self.reference_pid_condition_th = threading.Condition(
                    self.metadata_lock_th
                )
                self.reference_locked_pids_th = []

            self.fhs_logger.debug("Initialization success. Store root: %s", self.root)
        else:
            # Cannot instantiate or initialize FileHashStore without config
            err_msg = (
                "HashStore properties must be supplied." + f" Properties: {properties}"
            )
            self.fhs_logger.debug(err_msg)
            raise ValueError(err_msg)

    # Configuration and Related Methods

    @staticmethod
    def _load_properties(
        hashstore_yaml_path: Path, hashstore_required_prop_keys: List[str]
    ) -> Dict[str, Union[str, int]]:
        """Get and return the contents of the current HashStore configuration.

        :return: HashStore properties with the following keys (and values):
            - store_depth (int): Depth when sharding an object's hex digest.
            - store_width (int): Width of directories when sharding an object's hex digest.
            - store_algorithm (str): Hash algo used for calculating the object's hex digest.
            - store_metadata_namespace (str): Namespace for the HashStore's system metadata.
        """
        if not os.path.isfile(hashstore_yaml_path):
            err_msg = "'hashstore.yaml' not found in store root path."
            logging.critical(err_msg)
            raise FileNotFoundError(err_msg)

        # Open file
        with open(hashstore_yaml_path, "r", encoding="utf-8") as hs_yaml_file:
            yaml_data = yaml.safe_load(hs_yaml_file)

        # Get hashstore properties
        hashstore_yaml_dict = {}
        for key in hashstore_required_prop_keys:
            if key != "store_path":
                hashstore_yaml_dict[key] = yaml_data[key]
        logging.debug("Successfully retrieved 'hashstore.yaml' properties.")
        return hashstore_yaml_dict

    def _write_properties(self, properties: Dict[str, Union[str, int]]) -> None:
        """Writes 'hashstore.yaml' to FileHashStore's root directory with the respective
        properties object supplied.

        :param dict properties: A Python dictionary with the following keys (and values):
            - store_depth (int): Depth when sharding an object's hex digest.
            - store_width (int): Width of directories when sharding an object's hex digest.
            - store_algorithm (str): Hash algo used for calculating the object's hex digest.
            - store_metadata_namespace (str): Namespace for the HashStore's system metadata.
        """
        # If hashstore.yaml already exists, must throw exception and proceed with caution
        if os.path.isfile(self.hashstore_configuration_yaml):
            err_msg = "Configuration file 'hashstore.yaml' already exists."
            logging.error(err_msg)
            raise FileExistsError(err_msg)
        # Validate properties
        checked_properties = self._validate_properties(properties)

        # Collect configuration properties from validated & supplied dictionary
        (_, store_depth, store_width, store_algorithm, store_metadata_namespace,) = [
            checked_properties[property_name]
            for property_name in self.property_required_keys
        ]

        # Standardize algorithm value for cross-language compatibility
        # Note, this must be declared here because HashStore has not yet been initialized
        accepted_store_algorithms = ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"]
        if store_algorithm in accepted_store_algorithms:
            checked_store_algorithm = store_algorithm
        else:
            err_msg = (
                f"Algorithm supplied ({store_algorithm}) cannot be used as default for"
                f" HashStore. Must be one of: {', '.join(accepted_store_algorithms)}"
                f" which are DataONE controlled algorithm values"
            )
            logging.error(err_msg)
            raise ValueError(err_msg)

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
            "Configuration file written to: %s", self.hashstore_configuration_yaml
        )
        return

    @staticmethod
    def _build_hashstore_yaml_string(
        store_depth: int,
        store_width: int,
        store_algorithm: str,
        store_metadata_namespace: str,
    ) -> str:
        """Build a YAML string representing the configuration for a HashStore.

        :param int store_depth: Depth when sharding an object's hex digest.
        :param int store_width: Width of directories when sharding an object's hex digest.
        :param str store_algorithm: Hash algorithm used for calculating the object's hex digest.
        :param str store_metadata_namespace: Namespace for the HashStore's system metadata.

        :return: A YAML string representing the configuration for a HashStore.
        """
        hashstore_configuration = {
            "store_depth": store_depth,
            "store_width": store_width,
            "store_metadata_namespace": store_metadata_namespace,
            "store_algorithm": store_algorithm,
            "store_default_algo_list": [
                "MD5",
                "SHA-1",
                "SHA-256",
                "SHA-384",
                "SHA-512",
            ],
        }

        # The tabbing here is intentional otherwise the created .yaml will have extra tabs
        hashstore_configuration_comments = f"""
# Default configuration variables for HashStore

############### HashStore Config Notes ###############
############### Directory Structure ###############
# store_depth
# - Desired amount of directories when sharding an object to form the permanent address
# - **WARNING**: DO NOT CHANGE UNLESS SETTING UP NEW HASHSTORE
#
# store_width
# - Width of directories created when sharding an object to form the permanent address
# - **WARNING**: DO NOT CHANGE UNLESS SETTING UP NEW HASHSTORE
#
# Example:
# Below, objects are shown listed in directories that are 3 levels deep (DIR_DEPTH=3),
# with each directory consisting of 2 characters (DIR_WIDTH=2).
#    /var/filehashstore/objects
#    ├── 7f
#    │   └── 5c
#    │       └── c1
#    │           └── 8f0b04e812a3b4c8f686ce34e6fec558804bf61e54b176742a7f6368d6

############### Format of the Metadata ###############
# store_metadata_namespace
# - The default metadata format (ex. system metadata)

############### Hash Algorithms ###############
# store_algorithm
# - Hash algorithm to use when calculating object's hex digest for the permanent address
#
# store_default_algo_list
# - Algorithm values supported by python hashlib 3.9.0+ for File Hash Store (FHS)
# - The default algorithm list includes the hash algorithms calculated when storing an
# - object to disk and returned to the caller after successful storage.

"""

        hashstore_yaml_with_comments = hashstore_configuration_comments + yaml.dump(
            hashstore_configuration, sort_keys=False
        )

        return hashstore_yaml_with_comments

    def _verify_hashstore_properties(
        self, properties: Dict[str, Union[str, int]], prop_store_path: str
    ) -> None:
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
        if os.path.isfile(self.hashstore_configuration_yaml):
            self.fhs_logger.debug(
                "Config found (hashstore.yaml) at {%s}. Verifying properties.",
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
                        err_msg = (
                            f"Given properties ({key}: {properties[key]}) does not match."
                            + f" HashStore configuration ({key}: {hashstore_yaml_dict[key]})"
                            + f" found at: {self.hashstore_configuration_yaml}"
                        )
                        self.fhs_logger.critical(err_msg)
                        raise ValueError(err_msg)
        else:
            if os.path.exists(prop_store_path):
                # Check if HashStore exists and throw exception if found
                subfolders = ["objects", "metadata", "refs"]
                if any(
                    os.path.isdir(os.path.join(prop_store_path, sub))
                    for sub in subfolders
                ):
                    err_msg = (
                        "Unable to initialize HashStore. `hashstore.yaml` is not present but "
                        "conflicting HashStore directory exists. Please delete '/objects', "
                        "'/metadata' and/or '/refs' at the store path or supply a new path."
                    )
                    self.fhs_logger.critical(err_msg)
                    raise RuntimeError(err_msg)

    def _validate_properties(
        self, properties: Dict[str, Union[str, int]]
    ) -> Dict[str, Union[str, int]]:
        """Validate a properties dictionary by checking if it contains all the
        required keys and non-None values.

        :param dict properties: Dictionary containing filehashstore properties.

        :raises KeyError: If key is missing from the required keys.
        :raises ValueError: If value is missing for a required key.

        :return: The given properties object (that has been validated).
        """
        if not isinstance(properties, dict):
            err_msg = "Invalid argument expected a dictionary."
            self.fhs_logger.error(err_msg)
            raise ValueError(err_msg)

        # New dictionary for validated properties
        checked_properties = {}

        for key in self.property_required_keys:
            if key not in properties:
                err_msg = "Missing required key: {key}."
                self.fhs_logger.error(err_msg)
                raise KeyError(err_msg)

            value = properties.get(key)
            if value is None:
                err_msg = "Value for key: {key} is none."
                self.fhs_logger.error(err_msg)
                raise ValueError(err_msg)

            # Add key and values to checked_properties
            if key == "store_depth" or key == "store_width":
                # Ensure store depth and width are integers
                try:
                    checked_properties[key] = int(value)
                except Exception as err:
                    err_msg = (
                        "Unexpected exception when attempting to ensure store depth and width "
                        f"are integers. Details: {err}"
                    )
                    self.fhs_logger.error(err_msg)
                    raise ValueError(err_msg)
            else:
                checked_properties[key] = value

        return checked_properties

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

        if not os.path.isfile(self.hashstore_configuration_yaml):
            err_msg = "hashstore.yaml not found in store root path."
            self.fhs_logger.critical(err_msg)
            raise FileNotFoundError(err_msg)

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
        pid: Optional[str] = None,
        data: Optional[Union[str, bytes]] = None,
        additional_algorithm: Optional[str] = None,
        checksum: Optional[str] = None,
        checksum_algorithm: Optional[str] = None,
        expected_object_size: Optional[int] = None,
    ) -> "ObjectMetadata":
        if pid is None and self._check_arg_data(data):
            # If no pid is supplied, store the object only without tagging
            logging.debug("Request to store data only received.")
            object_metadata = self._store_data_only(data)
            self.fhs_logger.info(
                "Successfully stored object for cid: %s", object_metadata.cid
            )
        else:
            # Else the object will be stored and tagged
            self.fhs_logger.debug("Request to store object for pid: %s", pid)
            # Validate input parameters
            self._check_string(pid, "pid")
            self._check_arg_data(data)
            self._check_integer(expected_object_size)
            (
                additional_algorithm_checked,
                checksum_algorithm_checked,
            ) = self._check_arg_algorithms_and_checksum(
                additional_algorithm, checksum, checksum_algorithm
            )

            try:
                err_msg = (
                    f"Duplicate object request for pid: {pid}. Already in progress."
                )
                if self.use_multiprocessing:
                    with self.object_pid_condition_mp:
                        # Raise exception immediately if pid is in use
                        if pid in self.object_locked_pids_mp:
                            self.fhs_logger.error(err_msg)
                            raise StoreObjectForPidAlreadyInProgress(err_msg)
                else:
                    with self.object_pid_condition_th:
                        if pid in self.object_locked_pids_th:
                            logging.error(err_msg)
                            raise StoreObjectForPidAlreadyInProgress(err_msg)

                try:
                    self._synchronize_object_locked_pids(pid)

                    self.fhs_logger.debug("Attempting to store object for pid: %s", pid)
                    object_metadata = self._store_and_validate_data(
                        pid,
                        data,
                        additional_algorithm=additional_algorithm_checked,
                        checksum=checksum,
                        checksum_algorithm=checksum_algorithm_checked,
                        file_size_to_validate=expected_object_size,
                    )
                    self.fhs_logger.debug("Attempting to tag object for pid: %s", pid)
                    cid = object_metadata.cid
                    self.tag_object(pid, cid)
                    self.fhs_logger.info("Successfully stored object for pid: %s", pid)
                finally:
                    # Release pid
                    self._release_object_locked_pids(pid)
            except Exception as err:
                err_msg = (
                    f"Failed to store object for pid: {pid}. Reference files will not be "
                    f"created or tagged. Unexpected error: {err})"
                )
                self.fhs_logger.error(err_msg)
                raise err

        return object_metadata

    def tag_object(self, pid: str, cid: str) -> None:
        logging.debug("Tagging object cid: %s with pid: %s.", cid, pid)
        self._check_string(pid, "pid")
        self._check_string(cid, "cid")

        try:
            self._store_hashstore_refs_files(pid, cid)
        except HashStoreRefsAlreadyExists as hrae:
            err_msg = f"Reference files for pid: {pid} and {cid} already exist. Details: {hrae}"
            self.fhs_logger.error(err_msg)
            raise HashStoreRefsAlreadyExists(err_msg)
        except PidRefsAlreadyExistsError as praee:
            err_msg = f"A pid can only reference one cid. Details: {praee}"
            self.fhs_logger.error(err_msg)
            raise PidRefsAlreadyExistsError(err_msg)

    def delete_if_invalid_object(
        self,
        object_metadata: "ObjectMetadata",
        checksum: str,
        checksum_algorithm: str,
        expected_file_size: int,
    ) -> None:
        self._check_string(checksum, "checksum")
        self._check_string(checksum_algorithm, "checksum_algorithm")
        self._check_integer(expected_file_size)
        if object_metadata is None or not isinstance(object_metadata, ObjectMetadata):
            err_msg = (
                "'object_metadata' cannot be None. Must be a 'ObjectMetadata' object."
            )
            self.fhs_logger.error(err_msg)
            raise ValueError(err_msg)
        else:
            self.fhs_logger.info(
                "Called to verify object with id: %s", object_metadata.cid
            )
            object_metadata_hex_digests = object_metadata.hex_digests
            object_metadata_file_size = object_metadata.obj_size
            checksum_algorithm_checked = self._clean_algorithm(checksum_algorithm)

            # Throws exceptions if there's an issue
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
            except NonMatchingObjSize as nmose:
                self._delete_object_only(object_metadata.cid)
                logging.error(nmose)
                raise nmose
            except NonMatchingChecksum as mmce:
                self._delete_object_only(object_metadata.cid)
                raise mmce
            self.fhs_logger.info(
                "Object has been validated for cid: %s", object_metadata.cid
            )

    def store_metadata(
        self, pid: str, metadata: Union[str, bytes], format_id: Optional[str] = None
    ) -> str:
        self.fhs_logger.debug("Request to store metadata for pid: %s", pid)
        # Validate input parameters
        self._check_string(pid, "pid")
        self._check_arg_data(metadata)
        checked_format_id = self._check_arg_format_id(format_id, "store_metadata")
        pid_doc = self._computehash(pid + checked_format_id)

        sync_begin_debug_msg = (
            f" Adding pid: {pid} to locked list, with format_id: {checked_format_id} with doc "
            f"name: {pid_doc}"
        )
        sync_wait_msg = (
            f"Pid: {pid} is locked for format_id: {checked_format_id} with doc name: {pid_doc}. "
            f"Waiting."
        )
        if self.use_multiprocessing:
            with self.metadata_condition_mp:
                # Wait for the pid to release if it's in use
                while pid_doc in self.metadata_locked_docs_mp:
                    self.fhs_logger.debug(sync_wait_msg)
                    self.metadata_condition_mp.wait()
                # Modify metadata_locked_docs consecutively
                self.fhs_logger.debug(sync_begin_debug_msg)
                self.metadata_locked_docs_mp.append(pid_doc)
        else:
            with self.metadata_condition_th:
                while pid_doc in self.metadata_locked_docs_th:
                    self.fhs_logger.debug(sync_wait_msg)
                    self.metadata_condition_th.wait()
                self.fhs_logger.debug(sync_begin_debug_msg)
                self.metadata_locked_docs_th.append(pid_doc)

        try:
            metadata_cid = self._put_metadata(metadata, pid, pid_doc)
            info_msg = (
                f"Successfully stored metadata for pid: {pid} with format_id: "
                + checked_format_id
            )
            self.fhs_logger.info(info_msg)
            return str(metadata_cid)
        finally:
            # Release pid
            end_sync_debug_msg = (
                f"Releasing pid doc ({pid_doc}) from locked list for pid: {pid} with format_id: "
                + checked_format_id
            )
            if self.use_multiprocessing:
                with self.metadata_condition_mp:
                    self.fhs_logger.debug(end_sync_debug_msg)
                    self.metadata_locked_docs_mp.remove(pid_doc)
                    self.metadata_condition_mp.notify()
            else:
                with self.metadata_condition_th:
                    self.fhs_logger.debug(end_sync_debug_msg)
                    self.metadata_locked_docs_th.remove(pid_doc)
                    self.metadata_condition_th.notify()

    def retrieve_object(self, pid: str) -> IO[bytes]:
        self.fhs_logger.debug("Request to retrieve object for pid: %s", pid)
        self._check_string(pid, "pid")

        object_info_dict = self._find_object(pid)
        object_cid = object_info_dict.get("cid")
        entity = "objects"

        if object_cid:
            self.fhs_logger.debug(
                "Metadata exists for pid: %s, retrieving object.", pid
            )
            obj_stream = self._open(entity, object_cid)
        else:
            err_msg = f"No object found for pid: {pid}"
            self.fhs_logger.error(err_msg)
            raise ValueError(err_msg)
        self.fhs_logger.info("Retrieved object for pid: %s", pid)

        return obj_stream

    def retrieve_metadata(self, pid: str, format_id: Optional[str] = None) -> IO[bytes]:
        self.fhs_logger.debug("Request to retrieve metadata for pid: %s", pid)
        self._check_string(pid, "pid")
        checked_format_id = self._check_arg_format_id(format_id, "retrieve_metadata")

        entity = "metadata"
        metadata_directory = self._computehash(pid)
        if format_id is None:
            metadata_document_name = self._computehash(pid + self.sysmeta_ns)
        else:
            metadata_document_name = self._computehash(pid + checked_format_id)
        metadata_rel_path = (
            Path(*self._shard(metadata_directory)) / metadata_document_name
        )
        metadata_exists = self._exists(entity, str(metadata_rel_path))

        if metadata_exists:
            metadata_stream = self._open(entity, str(metadata_rel_path))
            self.fhs_logger.info("Retrieved metadata for pid: %s", pid)
            return metadata_stream
        else:
            err_msg = f"No metadata found for pid: {pid}"
            self.fhs_logger.error(err_msg)
            raise ValueError(err_msg)

    def delete_object(self, pid: str) -> None:
        self.fhs_logger.debug("Request to delete object for id: %s", pid)
        self._check_string(pid, "pid")

        objects_to_delete = []

        # Storing and deleting objects are synchronized together
        # Duplicate store object requests for a pid are rejected, but deleting an object
        # will wait for a pid to be released if it's found to be in use before proceeding.

        try:
            # Before we begin deletion process, we look for the `cid` by calling
            # `find_object` which will throw custom exceptions if there is an issue with
            # the reference files, which help us determine the path to proceed with.
            self._synchronize_object_locked_pids(pid)

            try:
                object_info_dict = self._find_object(pid)
                cid = object_info_dict.get("cid")

                # Proceed with next steps - cid has been retrieved without any issues
                # We must synchronize here based on the `cid` because multiple threads may
                # try to access the `cid_reference_file`
                self._synchronize_object_locked_cids(cid)

                try:
                    cid_ref_abs_path = object_info_dict.get("cid_refs_path")
                    pid_ref_abs_path = object_info_dict.get("pid_refs_path")
                    # Add pid refs file to be permanently deleted
                    objects_to_delete.append(
                        self._rename_path_for_deletion(pid_ref_abs_path)
                    )
                    # Remove pid from cid reference file
                    self._update_refs_file(Path(cid_ref_abs_path), pid, "remove")
                    # Delete cid reference file and object only if the cid refs file is empty
                    if os.path.getsize(cid_ref_abs_path) == 0:
                        debug_msg = (
                            f"Cid reference file is empty (size == 0): {cid_ref_abs_path} - "
                            + "deleting cid reference file and data object."
                        )
                        self.fhs_logger.debug(debug_msg)
                        objects_to_delete.append(
                            self._rename_path_for_deletion(cid_ref_abs_path)
                        )
                        obj_real_path = object_info_dict.get("cid_object_path")
                        objects_to_delete.append(
                            self._rename_path_for_deletion(obj_real_path)
                        )
                    # Remove all files confirmed for deletion
                    self._delete_marked_files(objects_to_delete)

                    # Remove metadata files if they exist
                    self.delete_metadata(pid)

                    info_string = (
                        f"Successfully deleted references, metadata and object associated"
                        + f" with pid: {pid}"
                    )
                    self.fhs_logger.info(info_string)
                    return

                finally:
                    # Release cid
                    self._release_object_locked_cids(cid)

            except OrphanPidRefsFileFound:
                warn_msg = (
                    f"Orphan pid reference file found for pid: {pid}. Skipping object deletion. "
                    + "Deleting pid reference file and related metadata documents."
                )
                self.fhs_logger.warning(warn_msg)

                # Delete pid refs file
                pid_ref_abs_path = self._get_hashstore_pid_refs_path(pid)
                objects_to_delete.append(
                    self._rename_path_for_deletion(pid_ref_abs_path)
                )
                # Remove metadata files if they exist
                self.delete_metadata(pid)
                # Remove all files confirmed for deletion
                self._delete_marked_files(objects_to_delete)
                return
            except RefsFileExistsButCidObjMissing:
                warn_msg = (
                    f"Reference files exist for pid: {pid}, but the data object is missing. "
                    + "Deleting pid reference file & related metadata documents. Handling cid "
                    + "reference file."
                )
                self.fhs_logger.warning(warn_msg)

                # Add pid refs file to be permanently deleted
                pid_ref_abs_path = self._get_hashstore_pid_refs_path(pid)
                objects_to_delete.append(
                    self._rename_path_for_deletion(pid_ref_abs_path)
                )
                # Remove pid from cid refs file
                pid_refs_cid = self._read_small_file_content(pid_ref_abs_path)
                try:
                    self._synchronize_object_locked_cids(pid_refs_cid)

                    cid_ref_abs_path = self._get_hashstore_cid_refs_path(pid_refs_cid)
                    # Remove if the pid refs is found
                    if self._is_string_in_refs_file(pid, cid_ref_abs_path):
                        self._update_refs_file(cid_ref_abs_path, pid, "remove")
                finally:
                    self._release_object_locked_cids(pid_refs_cid)

                # Remove metadata files if they exist
                self.delete_metadata(pid)
                # Remove all files confirmed for deletion
                self._delete_marked_files(objects_to_delete)
                return
            except PidNotFoundInCidRefsFile:
                warn_msg = (
                    f"Pid {pid} not found in cid reference file. Deleting pid reference "
                    + "file and related metadata documents."
                )
                self.fhs_logger.warning(warn_msg)

                # Add pid refs file to be permanently deleted
                pid_ref_abs_path = self._get_hashstore_pid_refs_path(pid)
                objects_to_delete.append(
                    self._rename_path_for_deletion(pid_ref_abs_path)
                )
                # Remove metadata files if they exist
                self.delete_metadata(pid)
                # Remove all files confirmed for deletion
                self._delete_marked_files(objects_to_delete)
                return
        finally:
            # Release pid
            self._release_object_locked_pids(pid)

    def delete_metadata(self, pid: str, format_id: Optional[str] = None) -> None:
        self.fhs_logger.debug("Request to delete metadata for pid: %s", pid)
        self._check_string(pid, "pid")
        checked_format_id = self._check_arg_format_id(format_id, "delete_metadata")
        metadata_directory = self._computehash(pid)
        rel_path = Path(*self._shard(metadata_directory))

        if format_id is None:
            # Delete all metadata documents
            objects_to_delete = []
            # Retrieve all metadata doc names
            metadata_rel_path = self._get_store_path("metadata") / rel_path
            metadata_file_paths = self._get_file_paths(metadata_rel_path)
            if metadata_file_paths is not None:
                for path in metadata_file_paths:
                    # Get document name
                    pid_doc = os.path.basename(path)
                    # Synchronize based on doc name
                    # Wait for the pid to release if it's in use
                    sync_begin_debug_msg = (
                        f"Adding pid: {pid} to locked list, with format_id: {checked_format_id} "
                        + f"with doc name: {pid_doc}"
                    )
                    sync_wait_msg = (
                        f"Pid: {pid} is locked for format_id: {checked_format_id} with doc name:"
                        + f" {pid_doc}. Waiting."
                    )
                    if self.use_multiprocessing:
                        with self.metadata_condition_mp:
                            # Wait for the pid to release if it's in use
                            while pid in self.metadata_locked_docs_mp:
                                self.fhs_logger.debug(sync_wait_msg)
                                self.metadata_condition_mp.wait()
                            # Modify metadata_locked_docs consecutively
                            self.fhs_logger.debug(sync_begin_debug_msg)
                            self.metadata_locked_docs_mp.append(pid_doc)
                    else:
                        with self.metadata_condition_th:
                            while pid in self.metadata_locked_docs_th:
                                self.fhs_logger.debug(sync_wait_msg)
                                self.metadata_condition_th.wait()
                            self.fhs_logger.debug(sync_begin_debug_msg)
                            self.metadata_locked_docs_th.append(pid_doc)
                    try:
                        # Mark metadata doc for deletion
                        objects_to_delete.append(self._rename_path_for_deletion(path))
                    finally:
                        # Release pid
                        end_sync_debug_msg = (
                            f"Releasing pid doc ({pid_doc}) from locked list for pid: {pid} with "
                            + f"format_id: {checked_format_id}"
                        )
                        if self.use_multiprocessing:
                            with self.metadata_condition_mp:
                                self.fhs_logger.debug(end_sync_debug_msg)
                                self.metadata_locked_docs_mp.remove(pid_doc)
                                self.metadata_condition_mp.notify()
                        else:
                            with self.metadata_condition_th:
                                self.fhs_logger.debug(end_sync_debug_msg)
                                self.metadata_locked_docs_th.remove(pid_doc)
                                self.metadata_condition_th.notify()

                # Delete metadata objects
                self._delete_marked_files(objects_to_delete)
                info_string = ("Successfully deleted all metadata for pid: {pid}",)
                self.fhs_logger.info(info_string)
        else:
            # Delete a specific metadata file
            pid_doc = self._computehash(pid + checked_format_id)
            # Wait for the pid to release if it's in use
            sync_begin_debug_msg = (
                f"Adding pid: {pid} to locked list, with format_id: {checked_format_id} with doc "
                + f"name: {pid_doc}"
            )
            sync_wait_msg = (
                f"Pid: {pid} is locked for format_id: {checked_format_id} with doc name:"
                + f" {pid_doc}. Waiting."
            )
            if self.use_multiprocessing:
                with self.metadata_condition_mp:
                    # Wait for the pid to release if it's in use
                    while pid in self.metadata_locked_docs_mp:
                        self.fhs_logger.debug(sync_wait_msg)
                        self.metadata_condition_mp.wait()
                    # Modify metadata_locked_docs consecutively
                    self.fhs_logger.debug(sync_begin_debug_msg)
                    self.metadata_locked_docs_mp.append(pid_doc)
            else:
                with self.metadata_condition_th:
                    while pid in self.metadata_locked_docs_th:
                        self.fhs_logger.debug(sync_wait_msg)
                        self.metadata_condition_th.wait()
                    self.fhs_logger.debug(sync_begin_debug_msg)
                    self.metadata_locked_docs_th.append(pid_doc)
            try:
                full_path_without_directory = Path(self.metadata / rel_path / pid_doc)
                self._delete("metadata", full_path_without_directory)
                info_string = (
                    f"Deleted metadata for pid: {pid} for format_id: {format_id}"
                )

                self.fhs_logger.info(info_string)
            finally:
                # Release pid
                end_sync_debug_msg = (
                    f"Releasing pid doc ({pid_doc}) from locked list for pid: {pid} with "
                    f"format_id: {checked_format_id}"
                )
                if self.use_multiprocessing:
                    with self.metadata_condition_mp:
                        self.fhs_logger.debug(end_sync_debug_msg)
                        self.metadata_locked_docs_mp.remove(pid_doc)
                        self.metadata_condition_mp.notify()
                else:
                    with self.metadata_condition_th:
                        self.fhs_logger.debug(end_sync_debug_msg)
                        self.metadata_locked_docs_th.remove(pid_doc)
                        self.metadata_condition_th.notify()

    def get_hex_digest(self, pid: str, algorithm: str) -> str:
        self.fhs_logger.debug("Request to get hex digest for object with pid: %s", pid)
        self._check_string(pid, "pid")
        self._check_string(algorithm, "algorithm")

        entity = "objects"
        algorithm = self._clean_algorithm(algorithm)
        object_cid = self._find_object(pid).get("cid")
        if not self._exists(entity, object_cid):
            err_msg = f"No object found for pid: {pid}"
            self.fhs_logger.error(err_msg)
            raise ValueError(err_msg)
        cid_stream = self._open(entity, object_cid)
        hex_digest = self._computehash(cid_stream, algorithm=algorithm)

        info_string = f"Successfully calculated hex digest for pid: {pid}. Hex Digest: {hex_digest}"
        logging.info(info_string)
        return hex_digest

    # FileHashStore Core Methods

    def _find_object(self, pid: str) -> Dict[str, str]:
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
                    if not self._exists("objects", pid_refs_cid):
                        err_msg = (
                            f"Reference file found for pid ({pid}) at {pid_ref_abs_path}"
                            + f", but object referenced does not exist, cid: {pid_refs_cid}"
                        )
                        self.fhs_logger.error(err_msg)
                        raise RefsFileExistsButCidObjMissing(err_msg)
                    else:
                        sysmeta_doc_name = self._computehash(pid + self.sysmeta_ns)
                        metadata_directory = self._computehash(pid)
                        metadata_rel_path = Path(*self._shard(metadata_directory))
                        sysmeta_full_path = (
                            self._get_store_path("metadata")
                            / metadata_rel_path
                            / sysmeta_doc_name
                        )
                        obj_info_dict = {
                            "cid": pid_refs_cid,
                            "cid_object_path": self._get_hashstore_data_object_path(
                                pid_refs_cid
                            ),
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
                    raise PidNotFoundInCidRefsFile(err_msg)
            else:
                err_msg = (
                    f"Pid reference file exists with cid: {pid_refs_cid} but cid reference file "
                    + f"not found: {cid_ref_abs_path} for pid: {pid}"
                )
                self.fhs_logger.error(err_msg)
                raise OrphanPidRefsFileFound(err_msg)
        else:
            err_msg = (
                f"Pid reference file not found for pid ({pid}): {pid_ref_abs_path}"
            )
            self.fhs_logger.error(err_msg)
            raise PidRefsDoesNotExist(err_msg)

    def _store_and_validate_data(
        self,
        pid: str,
        file: Union[str, bytes],
        additional_algorithm: Optional[str] = None,
        checksum: Optional[str] = None,
        checksum_algorithm: Optional[str] = None,
        file_size_to_validate: Optional[int] = None,
    ) -> "ObjectMetadata":
        """Store contents of `file` on disk, validate the object's parameters if provided,
        and tag/reference the object.

        :param str pid: Authority-based identifier.
        :param mixed file: Readable object or path to file.
        :param str additional_algorithm: Optional algorithm value to include when returning
            hex digests.
        :param str checksum: Optional checksum to validate object against hex digest before moving
            to permanent location.
        :param str checksum_algorithm: Algorithm value of the given checksum.
        :param int file_size_to_validate: Expected size of the object.

        :return: ObjectMetadata - object that contains the object id, object file size,
            and hex digest dictionary.
        """
        stream = Stream(file)

        self.fhs_logger.debug("Request to put object for pid: %s", pid)
        with closing(stream):
            (
                object_cid,
                obj_file_size,
                hex_digest_dict,
            ) = self._move_and_get_checksums(
                pid,
                stream,
                additional_algorithm,
                checksum,
                checksum_algorithm,
                file_size_to_validate,
            )

        object_metadata = ObjectMetadata(
            pid, object_cid, obj_file_size, hex_digest_dict
        )
        self.fhs_logger.debug("Successfully put object for pid: %s", pid)
        return object_metadata

    def _store_data_only(self, data: Union[str, bytes]) -> "ObjectMetadata":
        """Store an object to HashStore and return a metadata object containing the content
        identifier, object file size and hex digests dictionary of the default algorithms. This
        method does not validate the object and writes directly to `/objects` after the hex
        digests are calculated.

        :param mixed data: String or path to object.

        :raises IOError: If the object fails to store.
        :raises FileExistsError: If the file already exists.

        :return: ObjectMetadata - object that contains the object ID, object file
            size, and hex digest dictionary.
        """
        self.fhs_logger.debug("Request to store data object only.")

        try:
            # Ensure the data is a stream
            stream = Stream(data)

            # Get the hex digest dictionary
            with closing(stream):
                (
                    object_cid,
                    obj_file_size,
                    hex_digest_dict,
                ) = self._move_and_get_checksums(None, stream)

            object_metadata = ObjectMetadata(
                "HashStoreNoPid",
                object_cid,
                obj_file_size,
                hex_digest_dict,
            )
            # The permanent address of the data stored is based on the data's checksum
            cid = hex_digest_dict.get(self.algorithm)
            self.fhs_logger.debug("Successfully stored object with cid: %s", cid)
            return object_metadata
        # pylint: disable=W0718
        except Exception as err:
            err_msg = f"Failed to store object. Unexpected {err=}, {type(err)=}"
            self.fhs_logger.error(err_msg)
            raise err

    def _move_and_get_checksums(
        self,
        pid: Optional[str],
        stream: "Stream",
        additional_algorithm: Optional[str] = None,
        checksum: Optional[str] = None,
        checksum_algorithm: Optional[str] = None,
        file_size_to_validate: Optional[int] = None,
    ) -> Tuple[str, int, Dict[str, str]]:
        """Copy the contents of the `Stream` object onto disk. The copy process uses a temporary
        file to store the initial contents and returns a dictionary of algorithms and their
        hex digest values. If the file already exists, the method will immediately
        raise an exception. If an algorithm and checksum are provided, it will proceed to
        validate the object (and delete the temporary file created if the hex digest stored does
        not match what is provided).

        :param Optional[str] pid: Authority-based identifier.
        :param Stream stream: Object stream when saving.
        :param str additional_algorithm: Optional algorithm value to include when returning hex
            digests.
        :param str checksum: Optional checksum to validate the object against hex digest before
            moving to the permanent location.
        :param str checksum_algorithm: Algorithm value of the given checksum.
        :param int file_size_to_validate: Expected size of the object.

        :return: tuple - Object ID, object file size, and hex digest dictionary.
        """
        debug_msg = f"Creating temp file and calculating checksums for pid: {pid}"
        self.fhs_logger.debug(debug_msg)
        (
            hex_digests,
            tmp_file_name,
            tmp_file_size,
        ) = self._write_to_tmp_file_and_get_hex_digests(
            stream, additional_algorithm, checksum_algorithm
        )
        self.fhs_logger.debug("Temp file created: %s", tmp_file_name)

        # Objects are stored with their content identifier based on the store algorithm
        object_cid = hex_digests.get(self.algorithm)
        abs_file_path = self._build_hashstore_data_object_path(object_cid)

        # Only move file if it doesn't exist. We do not check before we create the tmp
        # file and calculate the hex digests because the given checksum could be incorrect.
        if not os.path.isfile(abs_file_path):
            # Files are stored once and only once
            self._verify_object_information(
                pid,
                checksum,
                checksum_algorithm,
                "objects",
                hex_digests,
                tmp_file_name,
                tmp_file_size,
                file_size_to_validate,
            )
            self._create_path(Path(os.path.dirname(abs_file_path)))
            try:
                debug_msg = f"Moving temp file to permanent location: {abs_file_path}"
                self.fhs_logger.debug(debug_msg)
                shutil.move(tmp_file_name, abs_file_path)
            except Exception as err:
                # Revert storage process
                err_msg = f" Unexpected Error: {err}"
                self.fhs_logger.warning(err_msg)
                if os.path.isfile(abs_file_path):
                    # Check to see if object exists before determining whether to delete
                    debug_msg = (
                        f"Permanent file found, checking hex digest for pid: {pid}"
                    )
                    self.fhs_logger.debug(debug_msg)
                    pid_checksum = self.get_hex_digest(pid, self.algorithm)
                    if pid_checksum == hex_digests.get(self.algorithm):
                        # If the checksums match, return and log warning
                        err_msg = (
                            f"Object exists at: {abs_file_path} but an unexpected issue has been "
                            + "encountered. Reference files will not be created and/or tagged."
                        )
                        self.fhs_logger.warning(err_msg)
                        raise err
                    else:
                        debug_msg = (
                            f"Object exists at {abs_file_path} but the pid object checksum "
                            + "provided does not  match what has been calculated. Deleting object. "
                            + "References will not be created and/or tagged.",
                        )
                        self.fhs_logger.debug(debug_msg)
                        self._delete("objects", abs_file_path)
                        raise err
                else:
                    self.fhs_logger.debug("Deleting temporary file: %s", tmp_file_name)
                    self._delete("tmp", tmp_file_name)
                    err_msg = (
                        f"Object has not been stored for pid: {pid} - an unexpected error has "
                        + f"occurred when moving tmp file to: {object_cid}. Reference files will "
                        + f"not be created and/or tagged. Error: {err}"
                    )
                    self.fhs_logger.warning(err_msg)
                    raise
        else:
            # If the data object already exists, do not move the file but attempt to verify it
            try:
                self._verify_object_information(
                    pid,
                    checksum,
                    checksum_algorithm,
                    "objects",
                    hex_digests,
                    tmp_file_name,
                    tmp_file_size,
                    file_size_to_validate,
                )
            except NonMatchingObjSize as nmose:
                # If any exception is thrown during validation, we do not tag.
                err_msg = (
                    f"Object already exists for pid: {pid}, deleting temp file. Reference files "
                    + "will not be created and/or tagged due to an issue with the supplied pid "
                    + f"object metadata. {str(nmose)}"
                )
                self.fhs_logger.debug(err_msg)
                raise NonMatchingObjSize(err_msg) from nmose
            except NonMatchingChecksum as nmce:
                # If any exception is thrown during validation, we do not tag.
                err_msg = (
                    f"Object already exists for pid: {pid}, deleting temp file. Reference files "
                    + "will not be created and/or tagged  due to an issue with the supplied pid "
                    + f"object metadata. {str(nmce)}"
                )
                self.fhs_logger.debug(err_msg)
                raise NonMatchingChecksum(err_msg) from nmce
            finally:
                # Ensure that the tmp file has been removed, the data object already exists, so it
                # is redundant. No exception is thrown so 'store_object' can proceed to tag object
                if os.path.isfile(tmp_file_name):
                    self._delete("tmp", tmp_file_name)

        return object_cid, tmp_file_size, hex_digests

    def _write_to_tmp_file_and_get_hex_digests(
        self,
        stream: "Stream",
        additional_algorithm: Optional[str] = None,
        checksum_algorithm: Optional[str] = None,
    ) -> Tuple[Dict[str, str], str, int]:
        """Create a named temporary file from a `Stream` object and return its filename
        and a dictionary of its algorithms and hex digests. If an additional and/or checksum
        algorithm is provided, it will add the respective hex digest to the dictionary if
        it is supported.

        :param Stream stream: Object stream.
        :param str additional_algorithm: Algorithm of additional hex digest to generate.
        :param str checksum_algorithm: Algorithm of additional checksum algo to generate.

        :return: tuple - hex_digest_dict, tmp.name
            - hex_digest_dict (dict): Algorithms and their hex digests.
            - tmp.name (str): Name of the temporary file created and written into.
            - tmp_file_size (int): Size of the data object
        """
        # Review additional hash object to digest and create new list
        algorithm_list_to_calculate = self._refine_algorithm_list(
            additional_algorithm, checksum_algorithm
        )
        tmp_root_path = self._get_store_path("objects") / "tmp"
        tmp = self._mktmpfile(tmp_root_path)

        self.fhs_logger.debug(
            "Tmp file created: %s, calculating hex digests.", tmp.name
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

            self.fhs_logger.debug(
                "Object stream successfully written to tmp file: %s", tmp.name
            )

            hex_digest_list = [
                hash_algorithm.hexdigest() for hash_algorithm in hash_algorithms
            ]
            hex_digest_dict = dict(zip(algorithm_list_to_calculate, hex_digest_list))
            tmp_file_size = os.path.getsize(tmp.name)
            # Ready for validation and atomic move
            tmp_file_completion_flag = True

            self.fhs_logger.debug("Hex digests calculated.")
            return hex_digest_dict, tmp.name, tmp_file_size
        # pylint: disable=W0718
        except Exception as err:
            err_msg = f"Unexpected {err=}, {type(err)=}"
            self.fhs_logger.error(err_msg)
            # pylint: disable=W0707,W0719
            raise Exception(err_msg)
        except KeyboardInterrupt:
            err_msg = "Keyboard interruption by user."
            self.fhs_logger.error(err_msg)
            if os.path.isfile(tmp.name):
                os.remove(tmp.name)
        finally:
            if not tmp_file_completion_flag:
                try:
                    if os.path.isfile(tmp.name):
                        os.remove(tmp.name)
                # pylint: disable=W0718
                except Exception as err:
                    err_msg = (
                        f"Unexpected {err=} while attempting to delete tmp file: "
                        + f"{tmp.name}, {type(err)=}"
                    )
                    self.fhs_logger.error(err_msg)

    def _mktmpfile(self, path: Path) -> IO[bytes]:
        """Create a temporary file at the given path ready to be written.

        :param Path path: Path to the file location.

        :return: file object - object with a file-like interface.
        """
        # Physically create directory if it doesn't exist
        if os.path.exists(path) is False:
            self._create_path(path)

        tmp = NamedTemporaryFile(dir=path, delete=False)

        # Delete tmp file if python interpreter crashes or thread is interrupted
        def delete_tmp_file():
            if os.path.isfile(tmp.name):
                os.remove(tmp.name)

        atexit.register(delete_tmp_file)

        # Ensure tmp file is created with desired permissions
        if self.f_mode is not None:
            old_mask = os.umask(0)
            try:
                os.chmod(tmp.name, self.f_mode)
            finally:
                os.umask(old_mask)
        return tmp

    def _store_hashstore_refs_files(self, pid: str, cid: str) -> None:
        """Create the pid refs file and create/update cid refs files in HashStore to establish
        the relationship between a 'pid' and a 'cid'.

        :param str pid: Persistent or authority-based identifier.
        :param str cid: Content identifier
        """
        try:
            self._synchronize_referenced_locked_pids(pid)
            self._synchronize_object_locked_cids(cid)

            try:
                # Prepare files and paths
                tmp_root_path = self._get_store_path("refs") / "tmp"
                pid_refs_path = self._get_hashstore_pid_refs_path(pid)
                cid_refs_path = self._get_hashstore_cid_refs_path(cid)
                # Create paths for pid ref file in '.../refs/pid' and cid ref file in '.../refs/cid'
                self._create_path(Path(os.path.dirname(pid_refs_path)))
                self._create_path(Path(os.path.dirname(cid_refs_path)))

                if os.path.isfile(pid_refs_path) and os.path.isfile(cid_refs_path):
                    # If both reference files exist, we confirm that reference files are where they
                    # are expected to be and throw an exception to inform the client that everything
                    # is in place - and include other issues for context
                    err_msg = (
                        f"Object with cid: {cid} exists and is tagged with pid: {pid}."
                    )
                    try:
                        self._verify_hashstore_references(
                            pid,
                            cid,
                            pid_refs_path,
                            cid_refs_path,
                            "Refs file already exists, verifying.",
                        )
                        self.fhs_logger.error(err_msg)
                        raise HashStoreRefsAlreadyExists(err_msg)
                    except Exception as e:
                        rev_msg = err_msg + " " + str(e)
                        self.fhs_logger.error(rev_msg)
                        raise HashStoreRefsAlreadyExists(err_msg)

                elif os.path.isfile(pid_refs_path) and not os.path.isfile(
                    cid_refs_path
                ):
                    # If pid refs exists, the pid has already been claimed and cannot be tagged we
                    # throw an exception immediately
                    error_msg = f"Pid refs file already exists for pid: {pid}."
                    self.fhs_logger.error(error_msg)
                    raise PidRefsAlreadyExistsError(error_msg)

                elif not os.path.isfile(pid_refs_path) and os.path.isfile(
                    cid_refs_path
                ):
                    debug_msg = (
                        f"Pid reference file does not exist for pid {pid} but cid refs file "
                        + f"found at: {cid_refs_path} for cid: {cid}"
                    )
                    self.fhs_logger.debug(debug_msg)
                    # Move the pid refs file
                    pid_tmp_file_path = self._write_refs_file(tmp_root_path, cid, "pid")
                    shutil.move(pid_tmp_file_path, pid_refs_path)
                    # Update cid ref files as it already exists
                    if not self._is_string_in_refs_file(pid, cid_refs_path):
                        self._update_refs_file(cid_refs_path, pid, "add")
                    self._verify_hashstore_references(
                        pid,
                        cid,
                        pid_refs_path,
                        cid_refs_path,
                        f"Updated existing cid refs file: {cid_refs_path} with pid: {pid}",
                    )
                    info_msg = f"Successfully updated cid: {cid} with pid: {pid}"
                    self.fhs_logger.info(info_msg)
                    return

                # Move both files after checking the existing status of refs files
                pid_tmp_file_path = self._write_refs_file(tmp_root_path, cid, "pid")
                cid_tmp_file_path = self._write_refs_file(tmp_root_path, pid, "cid")
                shutil.move(pid_tmp_file_path, pid_refs_path)
                shutil.move(cid_tmp_file_path, cid_refs_path)
                log_msg = "Refs files have been moved to their permanent location. Verifying refs."
                self._verify_hashstore_references(
                    pid, cid, pid_refs_path, cid_refs_path, log_msg
                )
                info_msg = f"Successfully updated cid: {cid} with pid: {pid}"
                self.fhs_logger.info(info_msg)

            except (
                HashStoreRefsAlreadyExists,
                PidRefsAlreadyExistsError,
            ) as expected_exceptions:
                raise expected_exceptions

            except Exception as ue:
                # For all other unexpected exceptions, we are to revert the tagging process as
                # much as possible. No exceptions from the reverting process will be thrown.
                err_msg = f"Unexpected exception: {ue}, reverting tagging process (untag obj)."
                self.fhs_logger.error(err_msg)
                self._untag_object(pid, cid)
                raise ue

        finally:
            # Release cid
            self._release_object_locked_cids(cid)
            self._release_reference_locked_pids(pid)

    def _untag_object(self, pid: str, cid: str) -> None:
        """Untags a data object in HashStore by deleting the 'pid reference file' and removing
        the 'pid' from the 'cid reference file'. This method will never delete a data
        object. `_untag_object` will attempt to proceed with as much of the untagging process as
        possible and swallow relevant exceptions.

        :param str cid: Content identifier
        :param str pid: Persistent or authority-based identifier.
        """
        self._check_string(pid, "pid")
        self._check_string(cid, "cid")

        untag_obj_delete_list = []

        # To untag a pid, the pid must be found and currently locked
        # The pid will not be released until this process is over
        self._check_reference_locked_pids(pid)

        # Before we begin the untagging process, we look for the `cid` by calling `find_object`
        # which will throw custom exceptions if there is an issue with the reference files,
        # which help us determine the path to proceed with.
        try:
            obj_info_dict = self._find_object(pid)
            cid_to_check = obj_info_dict["cid"]
            self._validate_and_check_cid_lock(pid, cid, cid_to_check)

            # Remove pid refs
            pid_refs_path = self._get_hashstore_pid_refs_path(pid)
            self._mark_pid_refs_file_for_deletion(
                pid, untag_obj_delete_list, pid_refs_path
            )
            # Remove pid from cid refs
            cid_refs_path = self._get_hashstore_cid_refs_path(cid)
            self._remove_pid_and_handle_cid_refs_deletion(
                pid, untag_obj_delete_list, cid_refs_path
            )
            # Remove all files confirmed for deletion
            self._delete_marked_files(untag_obj_delete_list)
            info_msg = f"Untagged pid: {pid} with cid: {cid}"
            self.fhs_logger.info(info_msg)

        except OrphanPidRefsFileFound as oprff:
            # `find_object` throws this exception when the cid refs file doesn't exist,
            # so we only need to delete the pid refs file (pid is already locked)
            pid_refs_path = self._get_hashstore_pid_refs_path(pid)
            cid_read = self._read_small_file_content(pid_refs_path)
            self._validate_and_check_cid_lock(pid, cid, cid_read)

            # Remove pid refs
            self._mark_pid_refs_file_for_deletion(
                pid, untag_obj_delete_list, pid_refs_path
            )
            self._delete_marked_files(untag_obj_delete_list)

            warn_msg = (
                f"Cid refs file does not exist for pid: {pid}. Deleted orphan pid refs file. "
                f"Additional info: {oprff}"
            )
            self.fhs_logger.warning(warn_msg)

        except RefsFileExistsButCidObjMissing as rfebcom:
            # `find_object` throws this exception when both pid/cid refs files exist but the
            # actual data object does not.
            pid_refs_path = self._get_hashstore_pid_refs_path(pid)
            cid_read = self._read_small_file_content(pid_refs_path)
            self._validate_and_check_cid_lock(pid, cid, cid_read)

            # Remove pid refs
            self._mark_pid_refs_file_for_deletion(
                pid, untag_obj_delete_list, pid_refs_path
            )
            # Remove pid from cid refs
            cid_refs_path = self._get_hashstore_cid_refs_path(cid)
            self._remove_pid_and_handle_cid_refs_deletion(
                pid, untag_obj_delete_list, cid_refs_path
            )
            # Remove all files confirmed for deletion
            self._delete_marked_files(untag_obj_delete_list)

            warn_msg = (
                f"data object for cid: {cid_read}. does not exist, but pid and cid references "
                + f"files found for pid: {pid}, Deleted pid and cid refs files. "
                + f"Additional info: {rfebcom}"
            )
            self.fhs_logger.warning(warn_msg)

        except PidNotFoundInCidRefsFile as pnficrf:
            # `find_object` throws this exception when both the pid and cid refs file exists
            # but the pid is not found in the cid refs file
            pid_refs_path = self._get_hashstore_pid_refs_path(pid)
            cid_read = self._read_small_file_content(pid_refs_path)
            self._validate_and_check_cid_lock(pid, cid, cid_read)

            # Remove pid refs
            self._mark_pid_refs_file_for_deletion(
                pid, untag_obj_delete_list, pid_refs_path
            )
            self._delete_marked_files(untag_obj_delete_list)

            warn_msg = (
                f"Pid not found in expected cid refs file for pid: {pid}. Deleted orphan pid refs "
                f"file. Additional info: {pnficrf}"
            )
            self.fhs_logger.warning(warn_msg)

        except PidRefsDoesNotExist as prdne:
            # `find_object` throws this exception if the pid refs file is not found
            # Check to see if pid is in the 'cid refs file' and attempt to remove it
            self._check_object_locked_cids(cid)

            # Remove pid from cid refs
            cid_refs_path = self._get_hashstore_cid_refs_path(cid)
            self._remove_pid_and_handle_cid_refs_deletion(
                pid, untag_obj_delete_list, cid_refs_path
            )
            # Remove all files confirmed for deletion
            self._delete_marked_files(untag_obj_delete_list)

            warn_msg = (
                "Pid refs file not found, removed pid from cid reference file for cid:"
                + f" {cid}. Additional info: {prdne}"
            )
            self.fhs_logger.warning(warn_msg)

    def _put_metadata(
        self, metadata: Union[str, bytes], pid: str, metadata_doc_name: str
    ) -> Path:
        """Store contents of metadata to `[self.root]/metadata` using the hash of the
        given PID and format ID as the permanent address.

        :param mixed metadata: String or path to metadata document.
        :param str pid: Authority-based identifier.
        :param str metadata_doc_name: Metadata document name

        :return: Address of the metadata document.
        """
        self.fhs_logger.debug("Request to put metadata for pid: %s", pid)
        # Create metadata tmp file and write to it
        metadata_stream = Stream(metadata)
        with closing(metadata_stream):
            metadata_tmp = self._mktmpmetadata(metadata_stream)

        # Get target and related paths (permanent location)
        metadata_directory = self._computehash(pid)
        metadata_document_name = metadata_doc_name
        rel_path = Path(*self._shard(metadata_directory))
        full_path = self._get_store_path("metadata") / rel_path / metadata_document_name

        # Move metadata to target path
        if os.path.isfile(metadata_tmp):
            try:
                parent = full_path.parent
                parent.mkdir(parents=True, exist_ok=True)
                # Metadata will be replaced if it exists
                shutil.move(metadata_tmp, full_path)
                self.fhs_logger.debug("Successfully put metadata for pid: %s", pid)
                return full_path
            except Exception as err:
                err_msg = f"Unexpected {err=}, {type(err)=}"
                self.fhs_logger.error(err_msg)
                if os.path.isfile(metadata_tmp):
                    # Remove tmp metadata, calling app must re-upload
                    self.fhs_logger.debug("Deleting metadata for pid: %s", pid)
                    self._delete("metadata", metadata_tmp)
                raise
        else:
            err_msg = (
                f"Attempted to move metadata for pid: {pid}, but metadata temp file not found:"
                + f" {metadata_tmp}"
            )
            self.fhs_logger.error(err_msg)
            raise FileNotFoundError(err_msg)

    def _mktmpmetadata(self, stream: "Stream") -> str:
        """Create a named temporary file with `stream` (metadata).

        :param Stream stream: Metadata stream.

        :return: Path/name of temporary file created and written into.
        """
        # Create temporary file in .../{store_path}/tmp
        tmp_root_path = self._get_store_path("metadata") / "tmp"
        tmp = self._mktmpfile(tmp_root_path)

        # tmp is a file-like object that is already opened for writing by default
        self.fhs_logger.debug("Writing stream to tmp metadata file: %s", tmp.name)
        with tmp as tmp_file:
            for data in stream:
                tmp_file.write(self._cast_to_bytes(data))

        self.fhs_logger.debug("Successfully written to tmp metadata file: %s", tmp.name)
        return tmp.name

    # FileHashStore Utility & Supporting Methods

    @staticmethod
    def _delete_marked_files(delete_list: list[str]) -> None:
        """Delete all the file paths in a given delete list.

        :param list delete_list: Persistent or authority-based identifier.
        """
        if delete_list is not None:
            for obj in delete_list:
                try:
                    os.remove(obj)
                except Exception as e:
                    warn_msg = f"Unable to remove {obj} in given delete_list. " + str(e)
                    logging.warning(warn_msg)
        else:
            raise ValueError("list cannot be None")

    def _mark_pid_refs_file_for_deletion(
        self, pid: str, delete_list: List[str], pid_refs_path: Path
    ) -> None:
        """Attempt to rename a pid refs file and add the renamed file to a provided list.

        :param str pid: Persistent or authority-based identifier.
        :param list delete_list: List to add the renamed pid refs file marked for deletion to
        :param path pid_refs_path: Path to the pid reference file
        """
        try:
            delete_list.append(self._rename_path_for_deletion(pid_refs_path))

        except Exception as e:
            err_msg = (
                f"Unable to delete pid refs file: {pid_refs_path} for pid: {pid}. {e}"
            )
            self.fhs_logger.error(err_msg)

    def _remove_pid_and_handle_cid_refs_deletion(
        self, pid: str, delete_list: List[str], cid_refs_path: Path
    ) -> None:
        """Attempt to remove a pid from a 'cid refs file' and add the 'cid refs file' to the
        delete list if it is empty.

        :param str pid: Persistent or authority-based identifier.
        :param list delete_list: List to add the renamed pid refs file marked for deletion to
        :param path cid_refs_path: Path to the pid reference file
        """
        try:
            # Remove pid from cid reference file
            self._update_refs_file(cid_refs_path, pid, "remove")
            # Delete cid reference file and object only if the cid refs file is empty
            if os.path.getsize(cid_refs_path) == 0:
                delete_list.append(self._rename_path_for_deletion(cid_refs_path))

        except Exception as e:
            err_msg = (
                f"Unable to delete remove pid from cid refs file: {cid_refs_path} for pid:"
                f" {pid}. " + str(e)
            )
            self.fhs_logger.error(err_msg)

    def _validate_and_check_cid_lock(
        self, pid: str, cid: str, cid_to_check: str
    ) -> None:
        """Confirm that the two content identifiers provided are equal and is locked to ensure
        thread safety.

        :param str pid: Persistent identifier
        :param str cid: Content identifier
        :param str cid_to_check: Cid that was retrieved or read
        """
        self._check_string(cid, "cid")
        self._check_string(cid_to_check, "cid_to_check")

        if cid != cid_to_check:
            err_msg = (
                f"_validate_and_check_cid_lock: cid provided: {cid_to_check} does not "
                f"match untag request for cid: {cid} and pid: {pid}"
            )
            self.fhs_logger.error(err_msg)
            raise ValueError(err_msg)
        self._check_object_locked_cids(cid)

    def _write_refs_file(self, path: Path, ref_id: str, ref_type: str) -> str:
        """Write a reference file in the supplied path into a temporary file.
        All `pid` or `cid` reference files begin with a single identifier, with the
        difference being that a cid reference file can potentially contain multiple
        lines of `pid`s that reference the `cid`.

        :param path path: Directory to write a temporary file into
        :param str ref_id: Authority-based, persistent or content identifier
        :param str ref_type: 'cid' or 'pid'

        :return: tmp_file_path - Path to the tmp refs file
        """
        self.fhs_logger.debug("Writing id (%s) into a tmp file in: %s", ref_id, path)
        try:
            with self._mktmpfile(path) as tmp_file:
                tmp_file_path = tmp_file.name
                with open(tmp_file_path, "w", encoding="utf8") as tmp_cid_ref_file:
                    if ref_type == "cid":
                        tmp_cid_ref_file.write(ref_id + "\n")
                    if ref_type == "pid":
                        tmp_cid_ref_file.write(ref_id)
                    return tmp_file_path

        except Exception as err:
            err_msg = (
                f"Failed to write cid refs file for pid: {ref_id} into path: {path}. "
                + f"Unexpected error: {err=}, {type(err)=}"
            )
            self.fhs_logger.error(err_msg)
            raise err

    def _update_refs_file(
        self, refs_file_path: Path, ref_id: str, update_type: str
    ) -> None:
        """Add or remove an existing ref from a refs file.

        :param path refs_file_path: Absolute path to the refs file.
        :param str ref_id: Authority-based or persistent identifier of the object.
        :param str update_type: 'add' or 'remove'
        """
        debug_msg = f"Updating ({update_type}) for ref_id: {ref_id} at refs file: {refs_file_path}."
        self.fhs_logger.debug(debug_msg)
        if not os.path.isfile(refs_file_path):
            err_msg = (
                f"Refs file: {refs_file_path} does not exist."
                + f"Cannot {update_type} ref_id: {ref_id}"
            )
            self.fhs_logger.error(err_msg)
            raise FileNotFoundError(err_msg)
        try:
            if update_type == "add":
                pid_found = self._is_string_in_refs_file(ref_id, refs_file_path)
                if not pid_found:
                    with open(refs_file_path, "a", encoding="utf8") as ref_file:
                        # Lock file for the shortest amount of time possible
                        file_descriptor = ref_file.fileno()
                        fcntl.flock(file_descriptor, fcntl.LOCK_EX)
                        ref_file.write(ref_id + "\n")
            if update_type == "remove":
                with open(refs_file_path, "r+", encoding="utf8") as ref_file:
                    # Lock file immediately, this process needs to complete
                    # before any others read/modify the content of resf file
                    file_descriptor = ref_file.fileno()
                    fcntl.flock(file_descriptor, fcntl.LOCK_EX)
                    new_pid_lines = [
                        cid_pid_line
                        for cid_pid_line in ref_file.readlines()
                        if cid_pid_line.strip() != ref_id
                    ]
                    ref_file.seek(0)
                    ref_file.writelines(new_pid_lines)
                    ref_file.truncate()
            debug_msg = (
                f"Update ({update_type}) for ref_id: {ref_id} "
                + f"completed on refs file: {refs_file_path}."
            )
            self.fhs_logger.debug(debug_msg)
        except Exception as err:
            err_msg = (
                f"Failed to {update_type} for ref_id: {ref_id}"
                + f" at refs file: {refs_file_path}. Unexpected {err=}, {type(err)=}"
            )
            self.fhs_logger.error(err_msg)
            raise err

    @staticmethod
    def _is_string_in_refs_file(ref_id: str, refs_file_path: Path) -> bool:
        """Check a reference file for a ref_id (`cid` or `pid`).

        :param str ref_id: Authority-based, persistent identifier or content identifier
        :param path refs_file_path: Path to the refs file

        :return: pid_found
        """
        with open(refs_file_path, "r", encoding="utf8") as ref_file:
            # Confirm that pid is not currently already tagged
            for line in ref_file:
                value = line.strip()
                if ref_id == value:
                    return True
        return False

    def _verify_object_information(
        self,
        pid: Optional[str],
        checksum: str,
        checksum_algorithm: str,
        entity: str,
        hex_digests: Dict[str, str],
        tmp_file_name: Optional[str],
        tmp_file_size: int,
        file_size_to_validate: int,
    ) -> None:
        """Evaluates an object's integrity - if there is a mismatch, deletes the object
        in question and raises an exception.

        :param Optional[str] pid: For logging purposes.
        :param str checksum: Value of the checksum to check.
        :param str checksum_algorithm: Algorithm of the checksum.
        :param str entity: Type of object ('objects' or 'metadata').
        :param dict hex_digests: Dictionary of hex digests to parse.
        :param Optional[str] tmp_file_name: Name of the temporary file.
        :param int tmp_file_size: Size of the temporary file.
        :param int file_size_to_validate: Expected size of the object.
        """
        if file_size_to_validate is not None and file_size_to_validate > 0:
            if file_size_to_validate != tmp_file_size:
                err_msg = (
                    f"Object file size calculated: {tmp_file_size} does not match with expected "
                    f"size: {file_size_to_validate}."
                )
                if pid is not None:
                    self._delete(entity, tmp_file_name)
                    err_msg_for_pid = (
                        f"{err_msg} Tmp file deleted and file not stored for pid: {pid}"
                    )
                    self.fhs_logger.debug(err_msg_for_pid)
                    raise NonMatchingObjSize(err_msg_for_pid)
                else:
                    self.fhs_logger.debug(err_msg)
                    raise NonMatchingObjSize(err_msg)
        if checksum_algorithm is not None and checksum is not None:
            if checksum_algorithm not in hex_digests:
                # Check to see if it is a supported algorithm
                self._clean_algorithm(checksum_algorithm)
                # If so, calculate the checksum and compare it
                if tmp_file_name is not None and pid is not None:
                    # Calculate the checksum from the tmp file
                    hex_digest_calculated = self._computehash(
                        tmp_file_name, algorithm=checksum_algorithm
                    )
                else:
                    # Otherwise, a data object has been stored without a pid
                    object_cid = hex_digests[self.algorithm]
                    cid_stream = self._open(entity, object_cid)
                    hex_digest_calculated = self._computehash(
                        cid_stream, algorithm=checksum_algorithm
                    )
                if hex_digest_calculated != checksum:
                    err_msg = (
                        f"Checksum_algorithm ({checksum_algorithm}) cannot be found in the "
                        + "default hex digests dict, but is supported. New checksum calculated: "
                        + f"{hex_digest_calculated}, does not match what has been provided: "
                        + checksum
                    )
                    self.fhs_logger.debug(err_msg)
                    raise NonMatchingChecksum(err_msg)
            else:
                hex_digest_stored = hex_digests[checksum_algorithm]
                if hex_digest_stored != checksum.lower():
                    err_msg = (
                        f"Hex digest and checksum do not match - file not stored for pid: {pid}. "
                        + f"Algorithm: {checksum_algorithm}. Checksum provided: {checksum} !="
                        + f" HexDigest: {hex_digest_stored}."
                    )
                    if pid is not None:
                        # Delete the tmp file
                        self._delete(entity, tmp_file_name)
                        err_msg_for_pid = (
                            err_msg + f" Tmp file ({tmp_file_name}) deleted."
                        )
                        self.fhs_logger.error(err_msg_for_pid)
                        raise NonMatchingChecksum(err_msg_for_pid)
                    else:
                        self.fhs_logger.error(err_msg)
                        raise NonMatchingChecksum(err_msg)

    def _verify_hashstore_references(
        self,
        pid: str,
        cid: str,
        pid_refs_path: Optional[Path] = None,
        cid_refs_path: Optional[Path] = None,
        additional_log_string: Optional[str] = None,
    ) -> None:
        """Verifies that the supplied pid and pid reference file and content have been
        written successfully.

        :param str pid: Authority-based or persistent identifier.
        :param str cid: Content identifier.
        :param path pid_refs_path: Path to pid refs file
        :param path cid_refs_path: Path to cid refs file
        :param str additional_log_string: String to append to exception statement
        """
        debug_msg = (
            f"Verifying pid ({pid}) and cid ({cid}) refs files. {additional_log_string}"
        )
        self.fhs_logger.debug(debug_msg)
        if pid_refs_path is None:
            pid_refs_path = self._get_hashstore_pid_refs_path(pid)
        if cid_refs_path is None:
            cid_refs_path = self._get_hashstore_cid_refs_path(cid)

        # Check that reference files were created
        if not os.path.isfile(pid_refs_path):
            err_msg = f" Pid refs file missing: {pid_refs_path}. Note: {additional_log_string}"
            self.fhs_logger.error(err_msg)
            raise PidRefsFileNotFound(err_msg)
        if not os.path.isfile(cid_refs_path):
            err_msg = (
                f"Cid refs file missing: {cid_refs_path}. Note: {additional_log_string}"
            )
            self.fhs_logger.error(err_msg)
            raise CidRefsFileNotFound(err_msg)
        # Check the content of the reference files
        # Start with the cid
        retrieved_cid = self._read_small_file_content(pid_refs_path)
        if retrieved_cid != cid:
            err_msg = (
                f"Pid refs file exists ({pid_refs_path}) but cid ({cid}) does not match."
                + f" Note: {additional_log_string}"
            )
            self.fhs_logger.error(err_msg)
            raise PidRefsContentError(err_msg)
        # Then the pid
        pid_found = self._is_string_in_refs_file(pid, cid_refs_path)
        if not pid_found:
            err_msg = (
                f"Cid refs file exists ({cid_refs_path}) but pid ({pid}) not found."
                + f" Note:  {additional_log_string}"
            )
            self.fhs_logger.error(err_msg)
            raise CidRefsContentError(err_msg)

    def _delete_object_only(self, cid: str) -> None:
        """Attempt to delete an object based on the given content identifier (cid). If the object
        has any pids references and/or a cid refs file exists, the object will not be deleted.

        :param str cid: Content identifier
        """
        try:
            cid_refs_abs_path = self._get_hashstore_cid_refs_path(cid)
            # If the refs file still exists, do not delete the object
            self._synchronize_object_locked_cids(cid)
            if os.path.isfile(cid_refs_abs_path):
                debug_msg = (
                    f"Cid reference file exists for: {cid}, skipping delete request."
                )
                self.fhs_logger.debug(debug_msg)

            else:
                self._delete("objects", cid)
                info_msg = f"Deleted object only for cid: {cid}"
                self.fhs_logger.info(info_msg)

        finally:
            self._release_object_locked_cids(cid)

    def _check_arg_algorithms_and_checksum(
        self,
        additional_algorithm: Optional[str],
        checksum: Optional[str],
        checksum_algorithm: Optional[str],
    ) -> Tuple[Optional[str], Optional[str]]:
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
        """
        additional_algorithm_checked = None
        if additional_algorithm != self.algorithm and additional_algorithm is not None:
            # Set additional_algorithm
            additional_algorithm_checked = self._clean_algorithm(additional_algorithm)
        checksum_algorithm_checked = None
        if checksum is not None:
            self._check_string(checksum_algorithm, "checksum_algorithm")
        if checksum_algorithm is not None:
            self._check_string(checksum, "checksum")
            # Set checksum_algorithm
            checksum_algorithm_checked = self._clean_algorithm(checksum_algorithm)
        return additional_algorithm_checked, checksum_algorithm_checked

    def _check_arg_format_id(self, format_id: str, method: str) -> str:
        """Determines the metadata namespace (format_id) to use for storing,
        retrieving, and deleting metadata.

        :param str format_id: Metadata namespace to review.
        :param str method: Calling method for logging purposes.

        :return: Valid metadata namespace.
        """
        if format_id and not format_id.strip():
            err_msg = f"FileHashStore - {method}: Format_id cannot be empty."
            self.fhs_logger.error(err_msg)
            raise ValueError(err_msg)
        elif format_id is None:
            # Use default value set by hashstore config
            checked_format_id = self.sysmeta_ns
        else:
            checked_format_id = format_id
        return checked_format_id

    def _refine_algorithm_list(
        self, additional_algorithm: Optional[str], checksum_algorithm: Optional[str]
    ) -> Set[str]:
        """Create the final list of hash algorithms to calculate.

        :param str additional_algorithm: Additional algorithm.
        :param str checksum_algorithm: Checksum algorithm.

        :return: De-duplicated list of hash algorithms.
        """
        algorithm_list_to_calculate = self.default_algo_list
        if checksum_algorithm is not None:
            self._clean_algorithm(checksum_algorithm)
            if checksum_algorithm in self.other_algo_list:
                debug_additional_other_algo_str = (
                    f"Checksum algo: {checksum_algorithm} found in other_algo_lists, adding to "
                    + f"list of algorithms to calculate."
                )
                self.fhs_logger.debug(debug_additional_other_algo_str)
                algorithm_list_to_calculate.append(checksum_algorithm)
        if additional_algorithm is not None:
            self._clean_algorithm(additional_algorithm)
            if additional_algorithm in self.other_algo_list:
                debug_additional_other_algo_str = (
                    f"Additional algo: {additional_algorithm} found in other_algo_lists, "
                    + f"adding to list of algorithms to calculate."
                )
                self.fhs_logger.debug(debug_additional_other_algo_str)
                algorithm_list_to_calculate.append(additional_algorithm)

        # Remove duplicates
        algorithm_list_to_calculate = set(algorithm_list_to_calculate)
        return algorithm_list_to_calculate

    def _clean_algorithm(self, algorithm_string: str) -> str:
        """Format a string and ensure that it is supported and compatible with
        the Python `hashlib` library.

        :param str algorithm_string: Algorithm to validate.

        :return: `hashlib` supported algorithm string.
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
            err_msg = f"Algorithm not supported: {cleaned_string}"
            self.fhs_logger.error(err_msg)
            raise UnsupportedAlgorithm(err_msg)
        return cleaned_string

    def _computehash(
        self, stream: Union["Stream", str, IO[bytes]], algorithm: Optional[str] = None
    ) -> str:
        """Compute the hash of a file-like object (or string) using the store algorithm by
        default or with an optional supported algorithm.

        :param mixed stream: A buffered stream (`io.BufferedReader`) of an object. A string is
            also acceptable as they are a sequence of characters (Python only).
        :param str algorithm: Algorithm of hex digest to generate.

        :return: Hex digest.
        """
        if algorithm is None:
            hash_obj = hashlib.new(self.algorithm)
        else:
            check_algorithm = self._clean_algorithm(algorithm)
            hash_obj = hashlib.new(check_algorithm)
        for data in stream:
            hash_obj.update(self._cast_to_bytes(data))
        hex_digest = hash_obj.hexdigest()
        return hex_digest

    def _shard(self, checksum: str) -> List[str]:
        """Splits the given checksum into a list of tokens of length `self.width`, followed by
        the remainder.

        This method divides the checksum into `self.depth` number of tokens, each with a fixed
        width of `self.width`, taken from the beginning of the checksum. Any leftover characters
        are added as the final element in the list.

        Example:
            For a checksum of '0d555ed77052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e',
            the result may be:
            ['0d', '55', '5e', 'd77052d7e166017f779cbc193357c3a5006ee8b8457230bcf7abcef65e']

        :param str checksum: The checksum string to be split into tokens.

        :return: A list where each element is a token of fixed width, with any leftover
        characters as the last element.
        """

        def compact(items: List[Any]) -> List[Any]:
            """Return only truthy elements of `items`."""
            # truthy_items = []
            # for item in items:
            #     if item:
            #         truthy_items.append(item)
            # return truthy_items
            return [item for item in items if item]

        # This creates a list of `depth` number of tokens with width
        # `width` from the first part of the id plus the remainder.
        hierarchical_list = compact(
            [checksum[i * self.width : self.width * (i + 1)] for i in range(self.depth)]
            + [checksum[self.depth * self.width :]]
        )

        return hierarchical_list

    def _count(self, entity: str) -> int:
        """Return the count of the number of files in the `root` directory.

        :param str entity: Desired entity type (ex. "objects", "metadata").

        :return: Number of files in the directory.
        """
        count = 0
        if entity == "objects":
            directory_to_count = self.objects
        elif entity == "metadata":
            directory_to_count = self.metadata
        elif entity == "pid":
            directory_to_count = self.pids
        elif entity == "cid":
            directory_to_count = self.cids
        elif entity == "tmp":
            directory_to_count = self.objects / "tmp"
        else:
            raise ValueError(
                f"entity: {entity} does not exist. Do you mean 'objects' or 'metadata'?"
            )

        for _, _, files in os.walk(directory_to_count):
            for _ in files:
                count += 1
        return count

    def _exists(self, entity: str, file: str) -> bool:
        """Check whether a given file id or path exists on disk.

        :param str entity: Desired entity type (e.g., "objects", "metadata").
        :param str file: The name of the file to check.

        :return: True if the file exists.
        """
        if entity == "objects":
            try:
                return bool(self._get_hashstore_data_object_path(file))
            except FileNotFoundError:
                return False
        if entity == "metadata":
            try:
                return bool(self._get_hashstore_metadata_path(file))
            except FileNotFoundError:
                return False

    def _open(
        self, entity: str, file: str, mode: str = "rb"
    ) -> Union[IO[bytes], IO[str]]:
        """Return open buffer object from given id or path. Caller is responsible
        for closing the stream.

        :param str entity: Desired entity type (ex. "objects", "metadata").
        :param str file: Address ID or path of file.
        :param str mode: Mode to open file in. Defaults to 'rb'.

        :return: An `io` stream dependent on the `mode`.
        """
        realpath = None
        if entity == "objects":
            realpath = self._get_hashstore_data_object_path(file)
        if entity == "metadata":
            realpath = self._get_hashstore_metadata_path(file)
        if realpath is None:
            raise IOError(f"Could not locate file: {file}")

        # pylint: disable=W1514
        # mode defaults to "rb"
        buffer = io.open(realpath, mode)
        return buffer

    def _delete(self, entity: str, file: Union[str, Path]) -> None:
        """Delete file using id or path. Remove any empty directories after
        deleting. No exception is raised if file doesn't exist.

        :param str entity: Desired entity type (ex. "objects", "metadata").
        :param str file: Address ID or path of file.
        """
        try:
            if entity == "tmp":
                realpath = file
            elif entity == "objects":
                realpath = self._get_hashstore_data_object_path(file)
            elif entity == "metadata":
                try:
                    realpath = self._get_hashstore_metadata_path(file)
                except FileNotFoundError:
                    # Swallow file not found exceptions for metadata
                    realpath = None
            elif os.path.isfile(file):
                # Check if the given path is an absolute path
                realpath = file
            else:
                raise IOError(
                    f"FileHashStore - delete(): Could not locate file: {file}"
                )
            if realpath is not None:
                os.remove(realpath)

        except Exception as err:
            err_msg = f"FileHashStore - delete(): Unexpected {err=}, {type(err)=}"
            self.fhs_logger.error(err_msg)
            raise err

    def _create_path(self, path: Path) -> None:
        """Physically create the folder path (and all intermediate ones) on disk.

        :param Path path: The path to create.
        :raises AssertionError: If the path already exists but is not a directory.
        """
        try:
            os.makedirs(path, self.d_mode)
        except FileExistsError:
            assert os.path.isdir(path), f"expected {path} to be a directory"

    def _get_store_path(self, entity: str) -> Path:
        """Return a path object to the root directory of the requested hashstore directory type

        :param str entity: Desired entity type: "objects", "metadata", "refs", "cid" and "pid".
        Note, "cid" and "pid" are refs specific directories.

        :return: Path to requested store entity type
        """
        if entity == "objects":
            return Path(self.objects)
        elif entity == "metadata":
            return Path(self.metadata)
        elif entity == "refs":
            return Path(self.refs)
        elif entity == "cid":
            return Path(self.cids)
        elif entity == "pid":
            return Path(self.pids)
        else:
            raise ValueError(
                f"entity: {entity} does not exist. Do you mean 'objects', 'metadata' or 'refs'?"
            )

    def _build_hashstore_data_object_path(self, hash_id: str) -> str:
        """Build the absolute file path for a given content identifier

        :param str hash_id: A hash ID to build a file path for.

        :return: An absolute file path for the specified hash ID.
        """
        paths = self._shard(hash_id)
        root_dir = self._get_store_path("objects")
        absolute_path = os.path.join(root_dir, *paths)
        return absolute_path

    def _get_hashstore_data_object_path(self, cid_or_relative_path: str) -> Path:
        """Get the expected path to a hashstore data object that exists using a content identifier.

        :param str cid_or_relative_path: Content identifier or relative path in '/objects' to check

        :return: Path to the data object referenced by the pid
        """
        expected_abs_data_obj_path = self._build_hashstore_data_object_path(
            cid_or_relative_path
        )
        if os.path.isfile(expected_abs_data_obj_path):
            return Path(expected_abs_data_obj_path)
        else:
            if os.path.isfile(cid_or_relative_path):
                # Check whether the supplied arg is an abs path that exists or not for convenience
                return Path(cid_or_relative_path)
            else:
                # Check the relative path
                relpath = os.path.join(self.objects, cid_or_relative_path)
                if os.path.isfile(relpath):
                    return Path(relpath)
                else:
                    raise FileNotFoundError(
                        "Could not locate a data object in '/objects' for the supplied "
                        + f"cid_or_relative_path: {cid_or_relative_path}"
                    )

    def _get_hashstore_metadata_path(self, metadata_relative_path: str) -> Path:
        """Return the expected metadata path to a hashstore metadata object that exists.

        :param str metadata_relative_path: Metadata path to check or relative path in '/metadata'
        to check

        :return: Path to the data object referenced by the pid
        """
        # Form the absolute path to the metadata file
        expected_abs_metadata_path = os.path.join(self.metadata, metadata_relative_path)
        if os.path.isfile(expected_abs_metadata_path):
            return Path(expected_abs_metadata_path)
        else:
            if os.path.isfile(metadata_relative_path):
                # Check whether the supplied arg is an abs path that exists or not for convenience
                return Path(metadata_relative_path)
            else:
                raise FileNotFoundError(
                    "Could not locate a metadata object in '/metadata' for the supplied "
                    + f"metadata_relative_path: {metadata_relative_path}"
                )

    def _get_hashstore_pid_refs_path(self, pid: str) -> Path:
        """Return the expected path to a pid reference file. The path may or may not exist.

        :param str pid: Persistent or authority-based identifier

        :return: Path to pid reference file
        """
        # The pid refs file is named after the hash of the pid using the store's algorithm
        hash_id = self._computehash(pid, self.algorithm)
        root_dir = self._get_store_path("pid")
        directories_and_path = self._shard(hash_id)
        pid_ref_file_abs_path = os.path.join(root_dir, *directories_and_path)
        return Path(pid_ref_file_abs_path)

    def _get_hashstore_cid_refs_path(self, cid: str) -> Path:
        """Return the expected path to a cid reference file. The path may or may not exist.

        :param str cid: Content identifier

        :return: Path to cid reference file
        """
        root_dir = self._get_store_path("cid")
        # The content identifier is to be split into directories as is supplied
        directories_and_path = self._shard(cid)
        cid_ref_file_abs_path = os.path.join(root_dir, *directories_and_path)
        return Path(cid_ref_file_abs_path)

    # Synchronization Methods

    def _synchronize_object_locked_pids(self, pid: str) -> None:
        """Threads must work with 'pid's one identifier at a time to ensure thread safety when
        handling requests to store, delete or tag pids.

        :param str pid: Persistent or authority-based identifier
        """
        if self.use_multiprocessing:
            with self.object_pid_condition_mp:
                # Wait for the cid to release if it's being tagged
                while pid in self.object_locked_pids_mp:
                    self.fhs_logger.debug(f"Pid ({pid}) is locked. Waiting.")
                    self.object_pid_condition_mp.wait()
                self.object_locked_pids_mp.append(pid)
            self.fhs_logger.debug(f"Synchronizing object_locked_pids_mp for pid: {pid}")
        else:
            with self.object_pid_condition_th:
                while pid in self.object_locked_pids_th:
                    self.fhs_logger.debug(f"Pid ({pid}) is locked. Waiting.")
                    self.object_pid_condition_th.wait()
                self.object_locked_pids_th.append(pid)
            self.fhs_logger.debug(f"Synchronizing object_locked_pids_th for pid: {pid}")

    def _release_object_locked_pids(self, pid: str) -> None:
        """Remove the given persistent identifier from 'object_locked_pids' and notify other
        waiting threads or processes.

        :param str pid: Persistent or authority-based identifier
        """
        if self.use_multiprocessing:
            with self.object_pid_condition_mp:
                self.object_locked_pids_mp.remove(pid)
                self.object_pid_condition_mp.notify()
            self.fhs_logger.debug(f"Releasing pid ({pid}) from object_locked_pids_mp.")
        else:
            # Release pid
            with self.object_pid_condition_th:
                self.object_locked_pids_th.remove(pid)
                self.object_pid_condition_th.notify()
            self.fhs_logger.debug(f"Releasing pid ({pid}) from object_locked_pids_th.")

    def _synchronize_object_locked_cids(self, cid: str) -> None:
        """Multiple threads may access a data object via its 'cid' or the respective 'cid
        reference file' (which contains a list of 'pid's that reference a 'cid') and this needs
        to be coordinated.

        :param str cid: Content identifier
        """
        if self.use_multiprocessing:
            with self.object_cid_condition_mp:
                # Wait for the cid to release if it's being tagged
                while cid in self.object_locked_cids_mp:
                    self.fhs_logger.debug(f"Cid ({cid}) is locked. Waiting.")
                    self.object_cid_condition_mp.wait()
                # Modify reference_locked_cids consecutively
                self.object_locked_cids_mp.append(cid)
            self.fhs_logger.debug(f"Synchronizing object_locked_cids_mp for cid: {cid}")
        else:
            with self.object_cid_condition_th:
                while cid in self.object_locked_cids_th:
                    self.fhs_logger.debug(f"Cid ({cid}) is locked. Waiting.")
                    self.object_cid_condition_th.wait()
                self.object_locked_cids_th.append(cid)
            self.fhs_logger.debug(f"Synchronizing object_locked_cids_th for cid: {cid}")

    def _check_object_locked_cids(self, cid: str) -> None:
        """Check that a given content identifier is currently locked (found in the
        'object_locked_cids' array). If it is not, an exception will be thrown.

        :param str cid: Content identifier
        """
        if self.use_multiprocessing:
            if cid not in self.object_locked_cids_mp:
                err_msg = f"Cid {cid} is not locked."
                self.fhs_logger.error(err_msg)
                raise IdentifierNotLocked(err_msg)
        else:
            if cid not in self.object_locked_cids_th:
                err_msg = f"Cid {cid} is not locked."
                self.fhs_logger.error(err_msg)
                raise IdentifierNotLocked(err_msg)

    def _release_object_locked_cids(self, cid: str) -> None:
        """Remove the given content identifier from 'object_locked_cids' and notify other
        waiting threads or processes.

        :param str cid: Content identifier
        """
        if self.use_multiprocessing:
            with self.object_cid_condition_mp:
                self.object_locked_cids_mp.remove(cid)
                self.object_cid_condition_mp.notify()
            self.fhs_logger.debug(
                f"Releasing cid ({cid}) from object_cid_condition_mp."
            )
        else:
            with self.object_cid_condition_th:
                self.object_locked_cids_th.remove(cid)
                self.object_cid_condition_th.notify()
            self.fhs_logger.debug(
                f"Releasing cid ({cid}) from object_cid_condition_th."
            )

    def _synchronize_referenced_locked_pids(self, pid: str) -> None:
        """Multiple threads may interact with a pid (to tag, untag, delete) and these actions
        must be coordinated to prevent unexpected behaviour/race conditions that cause chaos.

        :param str pid: Persistent or authority-based identifier
        """
        if self.use_multiprocessing:
            with self.reference_pid_condition_mp:
                # Wait for the pid to release if it's in use
                while pid in self.reference_locked_pids_mp:
                    self.fhs_logger.debug(f"Pid ({pid}) is locked. Waiting.")
                    self.reference_pid_condition_mp.wait()
                # Modify reference_locked_pids consecutively
                self.reference_locked_pids_mp.append(pid)
            self.fhs_logger.debug(
                f"Synchronizing reference_locked_pids_mp for pid: {pid}"
            )
        else:
            with self.reference_pid_condition_th:
                while pid in self.reference_locked_pids_th:
                    logging.debug(f"Pid ({pid}) is locked. Waiting.")
                    self.reference_pid_condition_th.wait()
                self.reference_locked_pids_th.append(pid)
            self.fhs_logger.debug(
                f"Synchronizing reference_locked_pids_th for pid: {pid}"
            )

    def _check_reference_locked_pids(self, pid: str) -> None:
        """Check that a given persistent identifier is currently locked (found in the
        'reference_locked_pids' array). If it is not, an exception will be thrown.

        :param str pid: Persistent or authority-based identifier
        """
        if self.use_multiprocessing:
            if pid not in self.reference_locked_pids_mp:
                err_msg = f"Pid {pid} is not locked."
                self.fhs_logger.error(err_msg)
                raise IdentifierNotLocked(err_msg)
        else:
            if pid not in self.reference_locked_pids_th:
                err_msg = f"Pid {pid} is not locked."
                self.fhs_logger.error(err_msg)
                raise IdentifierNotLocked(err_msg)

    def _release_reference_locked_pids(self, pid: str) -> None:
        """Remove the given persistent identifier from 'reference_locked_pids' and notify other
        waiting threads or processes.

        :param str pid: Persistent or authority-based identifier
        """
        if self.use_multiprocessing:
            with self.reference_pid_condition_mp:
                self.reference_locked_pids_mp.remove(pid)
                self.reference_pid_condition_mp.notify()
            self.fhs_logger.debug(
                f"Releasing pid ({pid}) from reference_locked_pids_mp."
            )
        else:
            # Release pid
            with self.reference_pid_condition_th:
                self.reference_locked_pids_th.remove(pid)
                self.reference_pid_condition_th.notify()
            self.fhs_logger.debug(
                f"Releasing pid ({pid}) from reference_locked_pids_th."
            )

    # Other Static Methods
    @staticmethod
    def _read_small_file_content(path_to_file: Path):
        """Read the contents of a file with the given path. This method is not optimized for
        large files - so it should only be used for small files (like reference files).

        :param path path_to_file: Path to the file to read

        :return: Content of the given file
        """
        with open(path_to_file, "r", encoding="utf8") as opened_path:
            content = opened_path.read()
            return content

    @staticmethod
    def _rename_path_for_deletion(path: Union[Path, str]) -> str:
        """Rename a given path by appending '_delete' and move it to the renamed path.

        :param Path path: Path to file to rename

        :return: Path to the renamed file
        """
        if isinstance(path, str):
            path = Path(path)
        delete_path = path.with_name(path.stem + "_delete" + path.suffix)
        shutil.move(path, delete_path)
        # TODO: Adjust all code for constructing paths to use path and revise accordingly
        return str(delete_path)

    @staticmethod
    def _get_file_paths(directory: Union[str, Path]) -> Optional[List[Path]]:
        """Get the file paths of a given directory if it exists

        :param mixed directory: String or path to directory.

        :raises FileNotFoundError: If the directory doesn't exist

        :return: file_paths - File paths of the given directory or None if directory doesn't exist
        """
        if os.path.exists(directory):
            files = os.listdir(directory)
            file_paths = [
                directory / file for file in files if os.path.isfile(directory / file)
            ]
            return file_paths
        else:
            return None

    @staticmethod
    def _check_arg_data(data: Union[str, os.PathLike, io.BufferedReader]) -> bool:
        """Checks a data argument to ensure that it is either a string, path, or stream
        object.

        :param data: Object to validate (string, path, or stream).
        :type data: str, os.PathLike, io.BufferedReader

        :return: True if valid.
        """
        if (
            not isinstance(data, str)
            and not isinstance(data, Path)
            and not isinstance(data, io.BufferedIOBase)
        ):
            err_msg = (
                "FileHashStore - _validate_arg_data: Data must be a path, string or buffered"
                + f" stream type. Data type supplied: {type(data)}"
            )
            logging.error(err_msg)
            raise TypeError(err_msg)
        if isinstance(data, str):
            if data.strip() == "":
                err_msg = (
                    "FileHashStore - _validate_arg_data: Data string cannot be empty."
                )
                logging.error(err_msg)
                raise TypeError(err_msg)
        return True

    @staticmethod
    def _check_integer(file_size: int) -> None:
        """Check whether a given argument is an integer and greater than 0;
        throw an exception if not.

        :param int file_size: File size to check.
        """
        if file_size is not None:
            if not isinstance(file_size, int):
                err_msg = (
                    "FileHashStore - _check_integer: size given must be an integer."
                    + f" File size: {file_size}. Arg Type: {type(file_size)}."
                )
                logging.error(err_msg)
                raise TypeError(err_msg)
            if file_size < 1:
                err_msg = "FileHashStore - _check_integer: size given must be > 0"
                logging.error(err_msg)
                raise ValueError(err_msg)

    @staticmethod
    def _check_string(string: str, arg: str) -> None:
        """Check whether a string is None or empty - or if it contains an illegal character;
        throws an exception if so.

        :param str string: Value to check.
        :param str arg: Name of the argument to check.
        """
        if string is None or string.strip() == "" or any(ch.isspace() for ch in string):
            method = inspect.stack()[1].function
            err_msg = (
                f"FileHashStore - {method}: {arg} cannot be None"
                + f" or empty, {arg}: {string}."
            )
            logging.error(err_msg)
            raise ValueError(err_msg)

    @staticmethod
    def _cast_to_bytes(text: any) -> bytes:
        """Convert text to a sequence of bytes using utf-8 encoding.

        :param Any text: String to convert.
        :return: Bytes with utf-8 encoding.
        """
        if not isinstance(text, bytes):
            text = bytes(text, "utf8")
        return text


class Stream:
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

    def __init__(self, obj: Union[IO[bytes], str, Path]):
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


@dataclass
class ObjectMetadata:
    """Represents metadata associated with an object.

    The `ObjectMetadata` class represents metadata associated with an object, including
    a persistent or authority-based identifier (`pid`), a content identifier (`cid`),
    the size of the object in bytes (`obj_size`), and an optional list of hex digests
    (`hex_digests`) to assist with validating objects.

    :param str pid: An authority-based or persistent identifier
    :param str cid: A unique identifier for the object (Hash ID, hex digest).
    :param int obj_size: The size of the object in bytes.
    :param dict hex_digests: A list of hex digests to validate objects
        (md5, sha1, sha256, sha384, sha512) (optional).
    """

    pid: str
    cid: str
    obj_size: int
    hex_digests: dict
