class BitwardenClientError(Exception):
    """Raised when a Bitwarden CLI operation fails."""


class BitwardenHttpError(BitwardenClientError):
    """Raised when ``bw serve`` returns a non-success HTTP status."""

    def __init__(self, message: str, *, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


class ConversionError(Exception):
    """Raised when a KeePass to Bitwarden conversion operation fails."""
