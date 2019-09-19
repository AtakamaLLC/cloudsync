class CloudException(Exception):
    def __init__(self, *args, original_exception=None):
        super().__init__(*args)
        self.original_exception = original_exception


class CloudFileNotFoundError(CloudException):       # ENOENT
    pass


class CloudTemporaryError(CloudException):
    pass


class CloudOutOfSpaceError(CloudTemporaryError):     # ENOSPC
    pass


class CloudFileExistsError(CloudException):
    pass


class CloudTokenError(CloudException):
    pass


class CloudDisconnectedError(CloudException):
    pass


class CloudCursorError(CloudException):
    pass
