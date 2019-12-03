from typing import NamedTuple, List


from .redir_server import *
from .oauth_config import *


class OAuthProviderInfo(NamedTuple):
    auth_url: str
    token_url: str
    scopes: List[str]

