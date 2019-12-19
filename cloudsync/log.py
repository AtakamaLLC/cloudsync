"""
Log initialization for cloudsync.  Adds the 'TRACE' level to the logger, which
only shows while unit testing cloudsync itself.
"""

# add TRACE named level, because libraries need it

import logging
logger = logging.getLogger(__package__)
if isinstance(logging.getLevelName('TRACE'), str):
    logging.addLevelName(5, 'TRACE')

# ses docs, this actually gets a number, because reasons
TRACE = logging.getLevelName('TRACE')
