class CloudException(Exception):                     # largely treated as a temporary error with a heavy backoff
    def __init__(self, *args, original_exception=None):
        super().__init__(*args)
        self.original_exception = original_exception


class CloudFileNotFoundError(CloudException):        # ENOENT
    pass


class CloudTemporaryError(CloudException):           # 'keep trying to sync this file'
    pass


class CloudFileNameError(CloudException):            # 'stop syncing unless renamed'
    pass


class CloudOutOfSpaceError(CloudTemporaryError):     # ENOSPC
    pass


class CloudFileExistsError(CloudException):          # EEXIST
    pass


class CloudTokenError(CloudException):               # 'creds don't work, refresh or reault'
    pass


class CloudDisconnectedError(CloudException):        # 'reconnect plz'
    pass


class CloudCursorError(CloudException):              # 'cursor is invalid'
    pass


