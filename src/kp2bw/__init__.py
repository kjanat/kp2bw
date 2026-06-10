import logging
from importlib.metadata import version

# Single source of truth for the package/CLI name: the import package name,
# which matches the distribution name and the console-script name in
# pyproject.toml. Drives both the metadata version lookup and the argparse prog,
# so "kp2bw" is never hardcoded in the runtime code.
__title__ = __name__
__version__ = version(__title__)

VERBOSE = 15
logging.addLevelName(VERBOSE, "VERBOSE")
