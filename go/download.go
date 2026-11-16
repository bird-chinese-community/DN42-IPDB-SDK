package ipdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

const (
	defaultTimeout = 30 * time.Second
	lockPollDelay  = 50 * time.Millisecond
	maxRedirects   = 10
	stagePrefix    = ".stage-"
	pendingPrefix  = ".current-"
)

// DownloadOptions configures Download. Timeout covers the writer-lock wait and
// every request; zero selects 30 seconds.
type DownloadOptions struct {
	CacheDir string
	BaseURL  string
	Timeout  time.Duration
}

// DownloadResult describes a refreshed cache. Database is built from the
// verified bytes and is owned by the caller, who closes it.
type DownloadResult struct {
	Directory      string    `json:"directory"`
	Changed        bool      `json:"changed"`
	RecoveredCache bool      `json:"recovered_cache"`
	Database       *Database `json:"-"`
}

// Download verifies a complete release before replacing the cache pointer.
// The Go cache occupies CacheDir/go/v2 and retains the current and previous version.
func Download(ctx context.Context, options DownloadOptions) (DownloadResult, error) {
	if options.CacheDir == "" {
		return DownloadResult{}, errors.New("CacheDir is required")
	}
	base, err := parseBaseURL(options.BaseURL)
	if err != nil {
		return DownloadResult{}, err
	}
	timeout, err := effectiveTimeout(options.Timeout)
	if err != nil {
		return DownloadResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cache := cacheDirectory(options.CacheDir)
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return DownloadResult{}, fmt.Errorf("create cache directory: %w", err)
	}
	unlock, err := lockCache(ctx, cache)
	if err != nil {
		return DownloadResult{}, err
	}
	defer unlock()
	return refresh(ctx, cache, newSource(base))
}

func effectiveTimeout(timeout time.Duration) (time.Duration, error) {
	switch {
	case timeout < 0:
		return 0, errors.New("timeout must not be negative")
	case timeout == 0:
		return defaultTimeout, nil
	}
	return timeout, nil
}

// lockCache takes the exclusive writer lock, polling until ctx ends.
func lockCache(ctx context.Context, cache string) (func(), error) {
	path := filepath.Join(cache, lockFile)
	guard := flock.New(path)
	locked, err := guard.TryLockContext(ctx, lockPollDelay)
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, fmt.Errorf("%w: %s: %w", ErrLockTimeout, path, err)
	}
	if err != nil {
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	if !locked {
		return nil, fmt.Errorf("%w: %s", ErrLockTimeout, path)
	}
	return func() { _ = guard.Close() }, nil
}

func refresh(ctx context.Context, cache string, src source) (DownloadResult, error) {
	checksums, err := src.manifest(ctx)
	if err != nil {
		return DownloadResult{}, err
	}
	previous, recovered, err := loadPrevious(cache)
	if err != nil {
		return DownloadResult{}, err
	}
	if previous != nil && maps.Equal(previous.Checksums, checksums) {
		directory := filepath.Join(cache, previous.Version)
		db, err := readVerified(directory, checksums)
		if err == nil {
			return DownloadResult{Directory: directory, Database: db}, nil
		}
		if !isRecoverable(err) {
			return DownloadResult{}, err
		}
		recovered = true
	}
	return install(ctx, cache, src, checksums, previous, recovered)
}

// loadPrevious reads the current pointer. A missing pointer is none; an
// unreadable pointer is none with recovered set.
func loadPrevious(cache string) (*pointer, bool, error) {
	current, err := readPointer(cache)
	switch {
	case err == nil:
		return &current, false, nil
	case errors.Is(err, ErrCacheMissing):
		return nil, false, nil
	case errors.Is(err, ErrInvalidBundle), errors.Is(err, ErrSizeLimit):
		return nil, true, nil
	}
	return nil, false, err
}

// install downloads a full bundle into a stage directory, moves it to its
// content-addressed version directory and switches the pointer.
func install(ctx context.Context, cache string, src source, checksums map[string]string, previous *pointer, recovered bool) (DownloadResult, error) {
	stage, err := os.MkdirTemp(cache, stagePrefix)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("create stage directory: %w", err)
	}
	defer os.RemoveAll(stage)
	files, err := src.bundleFiles(ctx, checksums)
	if err != nil {
		return DownloadResult{}, err
	}
	if err := writeFiles(stage, files); err != nil {
		return DownloadResult{}, err
	}
	db, err := parseBundle(files)
	if err != nil {
		return DownloadResult{}, err
	}
	version, err := versionOf(checksums)
	if err != nil {
		_ = db.Close()
		return DownloadResult{}, err
	}
	destination := filepath.Join(cache, version)
	created, err := placeVersion(ctx, stage, destination, checksums)
	if err != nil {
		_ = db.Close()
		return DownloadResult{}, err
	}
	if err := switchPointer(ctx, cache, pointer{Version: version, Checksums: checksums}, previous); err != nil {
		_ = db.Close()
		if created {
			_ = os.RemoveAll(destination)
		}
		return DownloadResult{}, err
	}
	return DownloadResult{Directory: destination, Changed: true, RecoveredCache: recovered, Database: db}, nil
}

func writeFiles(directory string, files map[string][]byte) error {
	for _, name := range bundleFiles {
		if err := writeSynced(filepath.Join(directory, name), files[name]); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

// writeSynced creates a 0600 file and flushes it to storage before closing.
func writeSynced(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return errors.Join(err, file.Close())
	}
	return file.Close()
}

func removeAll(ctx context.Context, path string) error {
	return retryWhileDenied(ctx, func() error { return os.RemoveAll(path) })
}

// placeVersion renames the stage to destination. An existing destination that
// passes the verified read is kept and the stage is discarded; a damaged one is
// replaced. It reports whether this run created the destination.
func placeVersion(ctx context.Context, stage, destination string, checksums map[string]string) (bool, error) {
	_, err := os.Stat(destination)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect %s: %w", destination, err)
	}
	if err == nil {
		existing, readErr := readVerified(destination, checksums)
		if readErr == nil {
			_ = existing.Close()
			return false, os.RemoveAll(stage)
		}
		if !isRecoverable(readErr) {
			return false, readErr
		}
		if err := removeAll(ctx, destination); err != nil {
			return false, fmt.Errorf("remove damaged version: %w", err)
		}
	}
	if err := os.Rename(stage, destination); err != nil {
		return false, fmt.Errorf("install version %s: %w", filepath.Base(destination), err)
	}
	return true, nil
}

// switchPointer writes the new pointer to a temporary file, prunes the cache
// and renames the temporary file over current.json.
func switchPointer(ctx context.Context, cache string, next pointer, previous *pointer) error {
	pending, err := writePending(cache, next)
	if err != nil {
		return err
	}
	defer os.Remove(pending)
	keep := []string{next.Version}
	if previous != nil {
		keep = append(keep, previous.Version)
	}
	if err := pruneCache(ctx, cache, filepath.Base(pending), keep); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("commit cache pointer: %w", err)
	}
	rename := func() error { return os.Rename(pending, filepath.Join(cache, pointerFile)) }
	if err := retryWhileDenied(ctx, rename); err != nil {
		return fmt.Errorf("commit cache pointer: %w", err)
	}
	return nil
}

func writePending(cache string, next pointer) (string, error) {
	data, err := json.Marshal(next)
	if err != nil {
		return "", fmt.Errorf("encode cache pointer: %w", err)
	}
	file, err := os.CreateTemp(cache, pendingPrefix)
	if err != nil {
		return "", fmt.Errorf("create pending pointer: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return "", fmt.Errorf("write pending pointer: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return "", fmt.Errorf("sync pending pointer: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(file.Name())
		return "", fmt.Errorf("close pending pointer: %w", err)
	}
	return file.Name(), nil
}

// pruneCache removes stage and pending entries of earlier runs (not
// currentPending) and version directories outside keep that hold exactly the
// seven bundle files. Other directories are left alone.
func pruneCache(ctx context.Context, cache, currentPending string, keep []string) error {
	entries, err := os.ReadDir(cache)
	if err != nil {
		return fmt.Errorf("list cache: %w", err)
	}
	for _, entry := range entries {
		prunable, err := isPrunable(cache, entry, currentPending, keep)
		if err != nil {
			return err
		}
		if !prunable {
			continue
		}
		if err := removeAll(ctx, filepath.Join(cache, entry.Name())); err != nil {
			return fmt.Errorf("prune %s: %w", entry.Name(), err)
		}
	}
	return nil
}

func isPrunable(cache string, entry os.DirEntry, currentPending string, keep []string) (bool, error) {
	name := entry.Name()
	switch {
	case strings.HasPrefix(name, stagePrefix):
		return true, nil
	case strings.HasPrefix(name, pendingPrefix):
		return name != currentPending, nil
	case entry.IsDir() && digestPattern.MatchString(name) && !slices.Contains(keep, name):
		return ownsVersion(filepath.Join(cache, name))
	}
	return false, nil
}

// ownsVersion reports whether a directory holds exactly the seven regular bundle files.
func ownsVersion(directory string) (bool, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return false, fmt.Errorf("list %s: %w", directory, err)
	}
	if len(entries) != len(bundleFiles) {
		return false, nil
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !slices.Contains(bundleFiles, entry.Name()) {
			return false, nil
		}
	}
	return true, nil
}

// parseBaseURL validates the release base URL and ensures a trailing slash.
func parseBaseURL(raw string) (*url.URL, error) {
	if raw == "" {
		raw = DefaultReleaseURL
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidURL, err)
	}
	switch {
	case parsed.Host == "":
		return nil, fmt.Errorf("%w: %q has no host", ErrInvalidURL, raw)
	case parsed.User != nil:
		return nil, fmt.Errorf("%w: %q contains credentials", ErrInvalidURL, raw)
	case parsed.RawQuery != "" || parsed.ForceQuery || strings.Contains(raw, "#"):
		return nil, fmt.Errorf("%w: %q contains a query or fragment", ErrInvalidURL, raw)
	case parsed.Scheme == "http" && !isLoopbackHost(parsed.Hostname()):
		return nil, fmt.Errorf("%w: http requires a loopback IP literal host, got %q", ErrInvalidURL, parsed.Hostname())
	case parsed.Scheme != "http" && parsed.Scheme != "https":
		return nil, fmt.Errorf("%w: unsupported scheme %q", ErrInvalidURL, parsed.Scheme)
	}
	if !strings.HasSuffix(parsed.Path, "/") {
		parsed.Path += "/"
		if parsed.RawPath != "" {
			parsed.RawPath += "/"
		}
	}
	return parsed, nil
}

func isLoopbackHost(host string) bool {
	address, err := netip.ParseAddr(host)
	return err == nil && address.Zone() == "" && (address.Is4() && address.IsLoopback() || address == netip.IPv6Loopback())
}

// source fetches release files from a validated base URL.
type source struct {
	base      *url.URL
	transport http.RoundTripper
}

// newSource returns a source that sends requests through the default
// transport (proxy environment included) and follows redirects itself, so that
// every hop and every unparsable Location is checked.
func newSource(base *url.URL) source {
	return source{base: base, transport: http.DefaultTransport}
}

// nextHop resolves a redirect Location against the current URL. A hop has no
// credentials and no fragment; it is https, or http on the host and port of a
// loopback http base URL. It may carry a query.
func nextHop(base, current *url.URL, location string) (*url.URL, error) {
	reference, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("%w: redirect location %q: %w", ErrInvalidURL, location, err)
	}
	target := current.ResolveReference(reference)
	switch {
	case strings.Contains(location, "#"):
		return nil, fmt.Errorf("%w: redirect to %s contains a fragment", ErrInvalidURL, target.Redacted())
	case target.User != nil:
		return nil, fmt.Errorf("%w: redirect to %s contains credentials", ErrInvalidURL, target.Redacted())
	case target.Scheme == "https":
		return target, nil
	case target.Scheme == "http" && base.Scheme == "http" && target.Host == base.Host:
		return target, nil
	}
	return nil, fmt.Errorf("%w: insecure redirect to %s", ErrInvalidURL, target.Redacted())
}

func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// fetch performs a GET and follows at most ten redirects under the hop rules.
// The caller closes the body of the returned response.
func (s source) fetch(ctx context.Context, address *url.URL) (*http.Response, error) {
	current := address
	for redirects := 0; ; redirects++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("download %s: %w", current.Redacted(), err)
		}
		request.Header.Set("User-Agent", "DN42-IPDB-SDK-Go")
		response, err := s.transport.RoundTrip(request)
		if err != nil {
			return nil, fmt.Errorf("download %s: %w", current.Redacted(), err)
		}
		if !isRedirect(response.StatusCode) {
			return response, nil
		}
		_ = response.Body.Close()
		location := response.Header.Get("Location")
		if location == "" {
			return nil, fmt.Errorf("%w: redirect %d from %s has no Location header", ErrInvalidURL, response.StatusCode, current.Redacted())
		}
		if redirects >= maxRedirects {
			return nil, fmt.Errorf("%w: more than %d redirects from %s", ErrInvalidURL, maxRedirects, address.Redacted())
		}
		if current, err = nextHop(s.base, current, location); err != nil {
			return nil, err
		}
	}
}

// manifest fetches checksums.json and returns the digests of the seven bundle files.
func (s source) manifest(ctx context.Context) (map[string]string, error) {
	data, err := s.get(ctx, manifestFile, MaxManifestBytes)
	if err != nil {
		return nil, err
	}
	checksums, err := parseChecksums(data)
	if err != nil {
		return nil, invalidBundle(manifestFile, err)
	}
	return checksums, nil
}

// bundleFiles downloads the seven files and checks each digest as it arrives.
func (s source) bundleFiles(ctx context.Context, checksums map[string]string) (map[string][]byte, error) {
	files := make(map[string][]byte, len(bundleFiles))
	for _, name := range bundleFiles {
		data, err := s.get(ctx, name, fileLimit(name))
		if err != nil {
			return nil, err
		}
		if checksum(data) != checksums[name] {
			return nil, fmt.Errorf("%w: %s", ErrChecksumMismatch, name)
		}
		files[name] = data
	}
	return files, nil
}

func (s source) get(ctx context.Context, name string, limit int64) ([]byte, error) {
	location := s.base.ResolveReference(&url.URL{Path: name})
	address := location.String()
	response, err := s.fetch(ctx, location)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s returned %d", ErrHTTPStatus, address, response.StatusCode)
	}
	if response.ContentLength > limit {
		return nil, fmt.Errorf("%w: %s", ErrSizeLimit, address)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", address, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w: %s", ErrSizeLimit, address)
	}
	return data, nil
}
