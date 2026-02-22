class BitwardenClientError(Exception):
    """Raised when a Bitwarden CLI operation fails."""


class ConversionError(Exception):
    """Raised when a KeePass to Bitwarden conversion operation fails."""
