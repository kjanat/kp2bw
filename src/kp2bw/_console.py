"""Shared Rich Console instance for logging and progress bars."""

from rich.console import Console

# Single console on stderr so stdout stays clean for any future pipe use.
# Both RichHandler (cli.py) and Progress (convert.py) reference this so that
# live-display rendering and log output coordinate and don't garble each other.
console = Console(stderr=True)
