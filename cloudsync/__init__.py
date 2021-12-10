"""

cloudsync enables simple cloud file-level sync with a variety of cloud providers

External modules:

cloudsync.Event
cloudsync.Provider
cloudsync.Sync

Example:

import cloudsync

# use directly
prov = cloudsync.get_provider('gdrive')
creds = prov.authenticate()
prov.connect(creds)
with open("file") as file:
    info = prov.create("/dest", file)

print("id of /dest is %s, hash of /dest is %s" % (info.oid, info.hash))

# use as sync
local = cloudsync.get_provider('file')
cs = cloudsync.CloudSync((local, prov), "/home/stuff", "/stuff")

# run forever
cs.run()
"""

__version__ = "%VERSION%"

from pystrict import strict, StrictError

# must be imported before other cloudsync imports
from .log import logger

# import modules into top level for convenience
from .exceptions import *
from .provider import *
from .event import *
from .sync import *
from .types import *
from .cs import *
from .long_poll import *
from .registry import *
from .notification import *
from .oauth import OAuthConfig
from .providers import *
from .command import *
from .smartsync import *
