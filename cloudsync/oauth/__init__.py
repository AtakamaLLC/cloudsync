"""
OAuth helpers for building new providers
"""

from typing import NamedTuple, List


from .redir_server import *
from .oauth_config import *


class OAuthProviderInfo(NamedTuple):
    """
    Providers can set their ._oauth_info protected member to one of these.
    """
    auth_url: str
    token_url: str
    scopes: List[str]
