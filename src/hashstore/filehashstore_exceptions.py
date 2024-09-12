"""FileHashStore custom exception module."""


class StoreObjectForPidAlreadyInProgress(Exception):
    """Custom exception thrown when called to store a data object for a pid that is already
    progress. A pid can only ever reference one data object/content identifier so duplicate
    requests are rejected immediately."""

    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = errors


class CidRefsContentError(Exception):
    """Custom exception thrown when verifying reference files and a cid refs
    file does not have a pid that is expected to be found."""

    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = errors


class CidRefsFileNotFound(Exception):
    """Custom exception thrown when verifying reference files and a cid refs
    file is not found."""

    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = errors


class CidRefsDoesNotExist(Exception):
    """Custom exception thrown when a cid refs file does not exist."""

    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = errors


class PidRefsContentError(Exception):
    """Custom exception thrown when verifying reference files and a pid refs
    file does not contain the cid that it is expected."""

    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = errors


class PidRefsFileNotFound(Exception):
    """Custom exception thrown when verifying reference files and a pid refs
    file is not found."""

    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = errors


class PidRefsAlreadyExistsError(Exception):
    """Custom exception thrown when a client calls 'tag_object' and the pid
    that is being tagged is already accounted for (has a pid refs file and
    is found in the cid refs file)."""

    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = errors


class PidRefsDoesNotExist(Exception):
    """Custom exception thrown when a pid refs file does not exist."""

    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = errors


class PidNotFoundInCidRefsFile(Exception):
    """Custom exception thrown when pid reference file exists with a cid, but
    the respective cid reference file does not contain the pid."""

    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = errors


class NonMatchingObjSize(Exception):
    """Custom exception thrown when verifying an object and the expected file size
    does not match what has been calculated."""

    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = errors


class NonMatchingChecksum(Exception):
    """Custom exception thrown when verifying an object and the expected checksum
    does not match what has been calculated."""

    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = errors


class RefsFileExistsButCidObjMissing(Exception):
    """Custom exception thrown when pid and cid refs file exists, but the
    cid object does not."""

    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = errors


class HashStoreRefsAlreadyExists(Exception):
    """Custom exception thrown when called to tag an object that is already tagged appropriately."""

    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = errors


class UnsupportedAlgorithm(Exception):
    """Custom exception thrown when a given algorithm is not supported in HashStore for
    calculating hashes/checksums, as the default store algo and/or other operations."""

    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = errors
