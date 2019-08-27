# add TRACE named level, and default logger to INFO

import logging
logger = logging.getLogger(__package__)
if isinstance(logging.getLevelName('TRACE'), str):
    logging.addLevelName(5, 'TRACE')
logger.setLevel(logging.INFO)

# ses docs, this actually gets a number, because reasons
TRACE = logging.getLevelName('TRACE')
