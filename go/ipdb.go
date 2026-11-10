// Package ipdb reads BIRDCC DN42 IPDB release bundles locally.
package ipdb

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/flock"
	"github.com/oschwald/maxminddb-golang/v2"
)

const DefaultReleaseURL = "https://github.com/bird-chinese-community/DN42-IPDB-Releases/releases/latest/download/"
const MaxDatabaseBytes = 32 << 20
const MaxManifestBytes = 64 << 10

var artifacts = []struct{ key, file, kind string }{
	{"country", "DN42-IPDB-Country.mmdb", "DN42-GeoIP2-Country"},
	{"city", "DN42-IPDB-City.mmdb", "DN42-GeoIP2-City"},
	{"asn", "DN42-IPDB-ASN.mmdb", "DN42-GeoLite2-ASN"},
	{"connection_type", "DN42-IPDB-Connection-Type.mmdb", "DN42-GeoIP2-Connection-Type"},
}
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var sidecars = []string{"asn-index.json", "metadata.json", "LICENSE-Unicode.txt"}

func artifactFiles() []string {
	files := make([]string, 0, len(artifacts)+len(sidecars))
	for _, artifact := range artifacts {
		files = append(files, artifact.file)
	}
	return append(files, sidecars...)
}

// Record retains standard GeoIP2 fields and the DN42 extension map.
type Record map[string]any

type Match struct {
	PrefixLength int    `json:"prefix_length"`
	Data         Record `json:"data"`
}

type Result struct {
	IP      string           `json:"ip"`
	Records map[string]Match `json:"records"`
}

type Database struct {
	readers map[string]*maxminddb.Reader
	asns    map[string]Record
	release Record
}

// Open loads all four databases into memory and checks their database types.
func Open(directory string) (*Database, error) {
	db := &Database{readers: make(map[string]*maxminddb.Reader)}
	indexBytes, err := readBounded(filepath.Join(directory, "asn-index.json"), MaxDatabaseBytes)
	if err != nil {
		return nil, fmt.Errorf("open ASN index: %w", err)
	}
	var index struct {
		SchemaVersion string            `json:"schema_version"`
		ASNs          map[string]Record `json:"asns"`
	}
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		return nil, fmt.Errorf("decode ASN index: %w", err)
	}
	if index.SchemaVersion != "2" || index.ASNs == nil {
		return nil, errors.New("invalid ASN index schema")
	}
	db.asns = index.ASNs
	metadataBytes, err := readBounded(filepath.Join(directory, "metadata.json"), MaxDatabaseBytes)
	if err != nil {
		return nil, fmt.Errorf("open release metadata: %w", err)
	}
	if err := json.Unmarshal(metadataBytes, &db.release); err != nil {
		return nil, fmt.Errorf("decode release metadata: %w", err)
	}
	if db.release["release_repository"] == nil || db.release["copyright"] == nil {
		return nil, errors.New("invalid release metadata")
	}
	for _, artifact := range artifacts {
		data, err := readBounded(filepath.Join(directory, artifact.file), MaxDatabaseBytes)
		if err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("open %s: %w", artifact.file, err)
		}
		reader, err := maxminddb.OpenBytes(data)
		if err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("decode %s: %w", artifact.file, err)
		}
		if reader.Metadata.DatabaseType != artifact.kind {
			_ = reader.Close()
			_ = db.Close()
			return nil, fmt.Errorf("%s: expected %s database", artifact.file, artifact.kind)
		}
		db.readers[artifact.key] = reader
	}
	return db, nil
}

// Lookup performs no network requests. Missing networks are absent from Records.
func (db *Database) Lookup(input string) (Result, error) {
	ip, err := netip.ParseAddr(input)
	if err != nil || ip.Zone() != "" {
		return Result{}, fmt.Errorf("invalid IP address: %q", input)
	}
	ip = ip.Unmap()
	output := Result{IP: ip.String(), Records: make(map[string]Match)}
	for key, reader := range db.readers {
		result := reader.Lookup(ip)
		if err := result.Err(); err != nil {
			return Result{}, fmt.Errorf("lookup %s: %w", key, err)
		}
		if !result.Found() {
			continue
		}
		var record Record
		if err := result.Decode(&record); err != nil {
			return Result{}, fmt.Errorf("decode %s: %w", key, err)
		}
		if len(record) > 0 {
			output.Records[key] = Match{PrefixLength: result.Prefix().Bits(), Data: record}
		}
	}
	return output, nil
}

func (db *Database) Metadata() map[string]maxminddb.Metadata {
	metadata := make(map[string]maxminddb.Metadata)
	for key, reader := range db.readers {
		metadata[key] = reader.Metadata
	}
	return metadata
}

// LookupASN returns observations for member prefixes; these do not classify an entire AS.
func (db *Database) LookupASN(asn uint32) (Record, bool) {
	record, found := db.asns[strconv.FormatUint(uint64(asn), 10)]
	return record, found
}

func (db *Database) ReleaseMetadata() Record { return db.release }

func (db *Database) Close() error {
	var failures []error
	for _, reader := range db.readers {
		failures = append(failures, reader.Close())
	}
	return errors.Join(failures...)
}

type DownloadOptions struct {
	CacheDir string
	BaseURL  string
	Timeout  time.Duration
}

type DownloadResult struct {
	Directory      string `json:"directory"`
	Changed        bool   `json:"changed"`
	RecoveredCache bool   `json:"recovered_cache,omitempty"`
}

type pointer struct {
	Version   string            `json:"version"`
	Checksums map[string]string `json:"checksums"`
}

func OpenCached(cacheDir string) (*Database, error) {
	cache := filepath.Join(cacheDir, "go", "v2")
	guard := flock.New(filepath.Join(cache, ".update.lock"))
	locked, err := guard.TryLock()
	if err != nil {
		return nil, fmt.Errorf("lock cache: %w", err)
	}
	if !locked {
		return nil, errors.New("cache update lock unavailable")
	}
	defer guard.Close()
	bytes, err := readBounded(filepath.Join(cache, "current.json"), MaxManifestBytes)
	if err != nil {
		return nil, err
	}
	var current pointer
	if err := json.Unmarshal(bytes, &current); err != nil {
		return nil, err
	}
	if !digestPattern.MatchString(current.Version) {
		return nil, errors.New("invalid cache version")
	}
	for _, file := range artifactFiles() {
		if !digestPattern.MatchString(current.Checksums[file]) {
			return nil, fmt.Errorf("invalid cache checksum: %s", file)
		}
	}
	directory := filepath.Join(cache, current.Version)
	if err := verifyFiles(directory, current.Checksums); err != nil {
		return nil, err
	}
	return Open(directory)
}

// Download verifies a complete release before replacing the cache pointer.
// The Go cache occupies CacheDir/go/v2 and retains the current and previous version.
func Download(ctx context.Context, options DownloadOptions) (DownloadResult, error) {
	if options.CacheDir == "" {
		return DownloadResult{}, errors.New("CacheDir is required")
	}
	base := options.BaseURL
	if base == "" {
		base = DefaultReleaseURL
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return DownloadResult{}, errors.New("invalid release base URL")
	}
	address, _ := netip.ParseAddr(parsed.Hostname())
	loopback := parsed.Scheme == "http" && address.IsLoopback()
	if parsed.Scheme != "https" && !loopback {
		return DownloadResult{}, errors.New("release URL requires HTTPS or loopback HTTP")
	}
	if !strings.HasSuffix(parsed.Path, "/") {
		parsed.Path += "/"
	}
	if options.Timeout <= 0 {
		options.Timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	client := &http.Client{CheckRedirect: func(request *http.Request, previous []*http.Request) error {
		if len(previous) >= 10 {
			return errors.New("too many release redirects")
		}
		if request.URL.Scheme != "https" && !(loopback && request.URL.Host == parsed.Host && request.URL.Scheme == "http") {
			return errors.New("insecure release redirect")
		}
		return nil
	}}
	cache := filepath.Join(options.CacheDir, "go", "v2")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return DownloadResult{}, err
	}
	guard := flock.New(filepath.Join(cache, ".update.lock"))
	locked, err := guard.TryLockContext(ctx, 50*time.Millisecond)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("lock cache: %w", err)
	}
	if !locked {
		return DownloadResult{}, errors.New("cache update lock unavailable")
	}
	defer guard.Close()
	manifest, err := fetch(ctx, client, parsed.ResolveReference(&url.URL{Path: "checksums.json"}).String(), MaxManifestBytes)
	if err != nil {
		return DownloadResult{}, err
	}
	var checksums map[string]string
	if err := json.Unmarshal(manifest, &checksums); err != nil {
		return DownloadResult{}, fmt.Errorf("decode checksum manifest: %w", err)
	}
	for _, file := range artifactFiles() {
		if !digestPattern.MatchString(checksums[file]) {
			return DownloadResult{}, fmt.Errorf("invalid checksum for %s", file)
		}
	}
	previous := ""
	recoveredCache := false
	pointerBytes, err := readBounded(filepath.Join(cache, "current.json"), MaxManifestBytes)
	if err == nil {
		var current pointer
		if err := json.Unmarshal(pointerBytes, &current); err != nil || !digestPattern.MatchString(current.Version) {
			recoveredCache = true
		} else {
			previous = current.Version
			directory := filepath.Join(cache, previous)
			unchanged := true
			for _, file := range artifactFiles() {
				if current.Checksums[file] != checksums[file] {
					unchanged = false
				}
			}
			if unchanged {
				if err := verifyFiles(directory, checksums); err != nil {
					return DownloadResult{}, err
				}
				return DownloadResult{Directory: directory}, nil
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return DownloadResult{}, err
	}
	stage, err := os.MkdirTemp(cache, ".stage-")
	if err != nil {
		return DownloadResult{}, err
	}
	defer os.RemoveAll(stage)
	for _, file := range artifactFiles() {
		data, err := fetch(ctx, client, parsed.ResolveReference(&url.URL{Path: file}).String(), MaxDatabaseBytes)
		if err != nil {
			return DownloadResult{}, err
		}
		if checksum(data) != checksums[file] {
			return DownloadResult{}, fmt.Errorf("checksum mismatch: %s", file)
		}
		if err := os.WriteFile(filepath.Join(stage, file), data, 0o600); err != nil {
			return DownloadResult{}, err
		}
	}
	if err := verifyFiles(stage, checksums); err != nil {
		return DownloadResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return DownloadResult{}, err
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return DownloadResult{}, err
	}
	version := hex.EncodeToString(random[:])
	destination := filepath.Join(cache, version)
	if err := os.Rename(stage, destination); err != nil {
		return DownloadResult{}, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(destination)
		}
	}()
	bytes, err := json.Marshal(pointer{Version: version, Checksums: checksums})
	if err != nil {
		return DownloadResult{}, err
	}
	pending, err := os.CreateTemp(cache, ".current-")
	if err != nil {
		return DownloadResult{}, err
	}
	defer os.Remove(pending.Name())
	if _, err := pending.Write(bytes); err != nil {
		_ = pending.Close()
		return DownloadResult{}, err
	}
	if err := pending.Close(); err != nil {
		return DownloadResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return DownloadResult{}, err
	}
	entries, err := os.ReadDir(cache)
	if err != nil {
		return DownloadResult{}, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !digestPattern.MatchString(entry.Name()) || entry.Name() == version || entry.Name() == previous {
			continue
		}
		directory := filepath.Join(cache, entry.Name())
		files, err := os.ReadDir(directory)
		if err != nil {
			return DownloadResult{}, err
		}
		owned := len(files) == len(artifactFiles())
		for _, file := range files {
			known := false
			for _, name := range artifactFiles() {
				if name == file.Name() {
					known = true
				}
			}
			if !known || !file.Type().IsRegular() {
				owned = false
			}
		}
		if owned {
			if err := os.RemoveAll(directory); err != nil {
				return DownloadResult{}, err
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return DownloadResult{}, err
	}
	if err := os.Rename(pending.Name(), filepath.Join(cache, "current.json")); err != nil {
		return DownloadResult{}, err
	}
	committed = true
	return DownloadResult{Directory: destination, Changed: true, RecoveredCache: recoveredCache}, nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("invalid file size: %s", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds size limit: %s", path)
	}
	return data, nil
}

func checksum(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func verifyFiles(directory string, checksums map[string]string) error {
	for _, file := range artifactFiles() {
		data, err := readBounded(filepath.Join(directory, file), MaxDatabaseBytes)
		if err != nil {
			return err
		}
		if checksum(data) != checksums[file] {
			return fmt.Errorf("checksum mismatch: %s", file)
		}
	}
	db, err := Open(directory)
	if err != nil {
		return err
	}
	return db.Close()
}

func fetch(ctx context.Context, client *http.Client, address string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "DN42-IPDB-SDK-Go")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", address, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", address, response.StatusCode)
	}
	if response.ContentLength > limit {
		return nil, fmt.Errorf("download %s: size limit exceeded", address)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("download %s: size limit exceeded", address)
	}
	return data, nil
}
