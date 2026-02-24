import logging
from importlib.metadata import version

__version__ = version("kp2bw")

VERBOSE = 15
logging.addLevelName(VERBOSE, "VERBOSE")
