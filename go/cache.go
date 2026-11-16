package ipdb

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// maxOpenAttempts bounds how often a reader follows a moving current.json.
const maxOpenAttempts = 3

type pointer struct {
	Version   string            `json:"version"`
	Checksums map[string]string `json:"checksums"`
}

// cacheDirectory is the Go cache of a cache root.
func cacheDirectory(cacheDir string) string { return filepath.Join(cacheDir, "go", "v2") }

// OpenCached opens the current cached bundle without networking and without
// taking the writer lock. It retries when the pointer moves during the read.
func OpenCached(cacheDir string) (*Database, error) {
	return openWithRetry(cacheDirectory(cacheDir), readVerified)
}

type verifiedReader func(directory string, checksums map[string]string) (*Database, error)

func openWithRetry(cache string, read verifiedReader) (*Database, error) {
	current, err := readPointer(cache)
	if err != nil {
		return nil, err
	}
	for attempt := 1; ; attempt++ {
		db, err := read(filepath.Join(cache, current.Version), current.Checksums)
		if err == nil {
			return db, nil
		}
		if attempt == maxOpenAttempts || !isStale(err) {
			return nil, err
		}
		next, pointerErr := readPointer(cache)
		if pointerErr != nil {
			return nil, errors.Join(err, pointerErr)
		}
		if next.Version == current.Version {
			return nil, err
		}
		current = next
	}
}

// isStale reports a read that a concurrent pointer switch can explain.
func isStale(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrChecksumMismatch)
}

// readVerified reads the seven files of a version once, compares their SHA-256
// digests with checksums and builds the bundle from those bytes.
func readVerified(directory string, checksums map[string]string) (*Database, error) {
	files, err := readBundleFiles(directory)
	if err != nil {
		return nil, err
	}
	if err := verifyChecksums(files, checksums); err != nil {
		return nil, err
	}
	return parseBundle(files)
}

func verifyChecksums(files map[string][]byte, checksums map[string]string) error {
	for _, name := range bundleFiles {
		if checksum(files[name]) != checksums[name] {
			return fmt.Errorf("%w: %s", ErrChecksumMismatch, name)
		}
	}
	return nil
}

// readPointer reads and validates current.json. A missing file is ErrCacheMissing.
func readPointer(cache string) (pointer, error) {
	path := filepath.Join(cache, pointerFile)
	data, err := readBounded(path, MaxManifestBytes)
	if errors.Is(err, os.ErrNotExist) {
		return pointer{}, fmt.Errorf("%w: %w", ErrCacheMissing, err)
	}
	if err != nil {
		return pointer{}, err
	}
	current, err := parsePointer(data)
	if err != nil {
		return pointer{}, invalidBundle(pointerFile, err)
	}
	return current, nil
}

func parsePointer(data []byte) (pointer, error) {
	var wire struct {
		Version   string          `json:"version"`
		Checksums json.RawMessage `json:"checksums"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return pointer{}, err
	}
	if !digestPattern.MatchString(wire.Version) {
		return pointer{}, fmt.Errorf("version %q is not 64 lowercase hex digits", wire.Version)
	}
	checksums, err := parseChecksums(wire.Checksums)
	if err != nil {
		return pointer{}, err
	}
	return pointer{Version: wire.Version, Checksums: checksums}, nil
}

// parseChecksums keeps the digests of the seven bundle files and ignores other keys.
func parseChecksums(data []byte) (map[string]string, error) {
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	if entries == nil {
		return nil, errors.New("checksums must be an object")
	}
	checksums := make(map[string]string, len(bundleFiles))
	for _, name := range bundleFiles {
		raw, found := entries[name]
		if !found {
			return nil, fmt.Errorf("missing checksum for %s", name)
		}
		var digest string
		if err := json.Unmarshal(raw, &digest); err != nil {
			return nil, fmt.Errorf("checksum for %s: %w", name, err)
		}
		if !digestPattern.MatchString(digest) {
			return nil, fmt.Errorf("checksum for %s is not a SHA-256 digest", name)
		}
		checksums[name] = digest
	}
	return checksums, nil
}

// versionOf names a version by the SHA-256 of the compact checksum JSON with keys sorted.
func versionOf(checksums map[string]string) (string, error) {
	canonical, err := json.Marshal(checksums)
	if err != nil {
		return "", fmt.Errorf("encode checksums: %w", err)
	}
	return checksum(canonical), nil
}
