"""
This is the complete list of exceptions that should be thrown by providers.
"""


class CloudException(Exception):                     # largely treated as a temporary error with a heavy backoff
    def __init__(self, *args, original_exception=None):
        super().__init__(*args)
        self.original_exception = original_exception


class CloudFileNotFoundError(CloudException):         # ENOENT
    pass


class CloudTemporaryError(CloudException):            # 'keep trying to sync this file'
    pass


class CloudFileNameError(CloudException):             # 'stop syncing unless renamed'
    pass


class CloudOutOfSpaceError(CloudTemporaryError):      # ENOSPC
    pass


class CloudRootMissingError(CloudTemporaryError):     # ENOENT, but treated differently!
    pass


class CloudFileExistsError(CloudException):           # EEXIST
    pass


class CloudTokenError(CloudException):                # 'creds don't work, refresh or reauth'
    pass


class CloudDisconnectedError(CloudException):         # 'reconnect plz'
    pass


class CloudCursorError(CloudException):               # 'cursor is invalid'
    pass


class CloudNamespaceError(CloudException):            # 'namespaces are not supported or the namespace is invalid'
    pass


class CloudTooManyRetriesError(CloudException):       # giving up on an operation after N unsucessful attempts
    pass
