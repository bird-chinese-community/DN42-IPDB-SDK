package ipdb

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
)

// DefaultReleaseURL is the release location used when DownloadOptions.BaseURL is empty.
const DefaultReleaseURL = "https://github.com/bird-chinese-community/DN42-IPDB-Releases/releases/latest/download/"

// Size limits enforced while reading local and downloaded files.
const (
	MaxDatabaseBytes = 32 << 20 // each .mmdb file and asn-index.json
	MaxMetadataBytes = 1 << 20  // metadata.json and LICENSE-Unicode.txt
	MaxManifestBytes = 64 << 10 // checksums.json and current.json
)

const (
	asnIndexFile = "asn-index.json"
	metadataFile = "metadata.json"
	licenseFile  = "LICENSE-Unicode.txt"
	pointerFile  = "current.json"
	manifestFile = "checksums.json"
	lockFile     = ".update.lock"
	schema       = "2"
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

var databases = []struct{ key, file, kind string }{
	{"country", "DN42-IPDB-Country.mmdb", "DN42-GeoIP2-Country"},
	{"city", "DN42-IPDB-City.mmdb", "DN42-GeoIP2-City"},
	{"asn", "DN42-IPDB-ASN.mmdb", "DN42-GeoLite2-ASN"},
	{"connection_type", "DN42-IPDB-Connection-Type.mmdb", "DN42-GeoIP2-Connection-Type"},
}

// bundleFiles lists the four databases followed by the three sidecar files.
var bundleFiles = listBundleFiles()

func listBundleFiles() []string {
	files := make([]string, 0, len(databases)+3)
	for _, database := range databases {
		files = append(files, database.file)
	}
	return append(files, asnIndexFile, metadataFile, licenseFile)
}

func fileLimit(name string) int64 {
	if slices.Contains([]string{metadataFile, licenseFile}, name) {
		return MaxMetadataBytes
	}
	return MaxDatabaseBytes
}

func checksum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// readBounded reads a regular file and stops at limit bytes.
func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrInvalidBundle, path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%w: %s", ErrSizeLimit, path)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: %s", ErrSizeLimit, path)
	}
	return data, nil
}

// isRecoverable reports whether a failed verified read means the cached
// version is missing or damaged, so a full download can replace it.
func isRecoverable(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrChecksumMismatch) ||
		errors.Is(err, ErrInvalidBundle) || errors.Is(err, ErrSizeLimit)
}
