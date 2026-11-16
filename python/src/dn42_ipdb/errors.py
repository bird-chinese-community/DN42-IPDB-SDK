"""Exception types raised by the SDK."""


class Dn42IpdbError(Exception):
    """Base class of every error raised for DN42 IPDB data."""


class InvalidAddressError(Dn42IpdbError, ValueError):
    """The IP address is malformed or carries a zone identifier."""


class InvalidAsnError(Dn42IpdbError, ValueError):
    """The ASN is not an integer in 0..4294967295."""


class InvalidUrlError(Dn42IpdbError, ValueError):
    """A release base URL or redirect target is not allowed."""


class InvalidBundleError(Dn42IpdbError, ValueError):
    """A bundle file is missing, malformed or inconsistent."""

    def __init__(self, file: str, reason: str) -> None:
        super().__init__(f"invalid bundle file {file}: {reason}")
        self.file = file
        self.reason = reason


class ChecksumMismatchError(InvalidBundleError):
    """A file digest differs from the digest recorded for it."""

    def __init__(self, file: str) -> None:
        super().__init__(file, "checksum mismatch")


class SizeLimitError(Dn42IpdbError, ValueError):
    """A file or HTTP response exceeds its size limit."""

    def __init__(self, target: str, limit: int) -> None:
        super().__init__(f"{target} exceeds the {limit} byte limit")
        self.target = target
        self.limit = limit


class HttpStatusError(Dn42IpdbError):
    """The release server answered with a status other than 200."""

    def __init__(self, url: str, status: int) -> None:
        super().__init__(f"{url} returned HTTP status {status}")
        self.url = url
        self.status = status


class LockTimeoutError(Dn42IpdbError, TimeoutError):
    """The cache writer lock was not acquired before the deadline."""


class CacheMissingError(Dn42IpdbError, FileNotFoundError):
    """A cache file or directory does not exist."""

    def __init__(self, path: str) -> None:
        super().__init__(f"cache path is missing: {path}")
        self.path = path
