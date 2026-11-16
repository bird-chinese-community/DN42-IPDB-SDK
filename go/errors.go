package ipdb

import (
	"errors"
	"fmt"
)

// Error categories. Returned errors wrap one of these sentinels, so callers
// match them with errors.Is. The underlying cause stays in the chain.
var (
	ErrInvalidAddress   = errors.New("invalid IP address")
	ErrInvalidURL       = errors.New("invalid release URL")
	ErrInvalidBundle    = errors.New("invalid bundle")
	ErrChecksumMismatch = errors.New("checksum mismatch")
	ErrSizeLimit        = errors.New("size limit exceeded")
	ErrHTTPStatus       = errors.New("unexpected HTTP status")
	ErrLockTimeout      = errors.New("cache update lock timeout")
	ErrCacheMissing     = errors.New("cache missing")
)

func invalidBundle(file string, cause error) error {
	return fmt.Errorf("%w: %s: %w", ErrInvalidBundle, file, cause)
}

func invalidBundleReason(file, format string, args ...any) error {
	return fmt.Errorf("%w: %s: %s", ErrInvalidBundle, file, fmt.Sprintf(format, args...))
}
