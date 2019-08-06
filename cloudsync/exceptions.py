class CloudException(Exception):
    pass


class CloudFileNotFoundError(CloudException):
    pass


class CloudTemporaryError(CloudException):
    pass


class CloudFileExistsError(CloudException):
    pass


class CloudTokenError(CloudException):
    pass


class CloudDisconnectedError(CloudException):
    pass
