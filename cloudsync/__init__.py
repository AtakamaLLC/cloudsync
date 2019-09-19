"""

cloudsync enables simple cloud file-level sync with a variety of cloud providers

External modules:

cloudsync.Event
cloudsync.Provider
cloudsync.Sync

Example:

import cloudsync

prov = cloudsync.Provider('GDrive', token="237846234236784283")

info = prov.upload(file, "/dest")
print ("id of /dest is %s, hash of /dest is %s" % (info.id, info.hash))

Command-line example:

cloudsync -p gdrive --token "236723782347823642786" -f ~/gdrive-folder --daemon

"""

__version__ = "0.2.8"

from pystrict import strict, StrictError

# must be imported before other cloudsync imports
from .log import logger

# import modules into top level for convenience
from .provider import *
from .event import *
from .sync import *
from .exceptions import *
from .types import *
from .cs import *

from .command import main

if __name__ == "__main__":
    main()
