package ipdb

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestOpenCachedMissing(t *testing.T) {
	if _, err := OpenCached(t.TempDir()); !errors.Is(err, ErrCacheMissing) {
		t.Fatalf("expected cache-missing error, got %v", err)
	}
}

func TestOpenCachedRejectsDamage(t *testing.T) {
	options := installedCache(t)
	cache := cacheDirectory(options.CacheDir)
	target := filepath.Join(cache, fixtureVersion, "DN42-IPDB-City.mmdb")
	if err := os.WriteFile(target, []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCached(options.CacheDir); !errors.Is(err, ErrChecksumMismatch) || !strings.Contains(err.Error(), "DN42-IPDB-City.mmdb") {
		t.Fatalf("expected checksum mismatch naming the file, got %v", err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCached(options.CacheDir); !errors.Is(err, ErrInvalidBundle) || !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "DN42-IPDB-City.mmdb") {
		t.Fatalf("expected invalid-bundle error naming the file with the not-found cause, got %v", err)
	}
	if err := os.WriteFile(filepath.Join(cache, "current.json"), []byte(`{"version":"abc","checksums":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCached(options.CacheDir); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("expected invalid pointer error, got %v", err)
	}
}

func TestConcurrentOpenCached(t *testing.T) {
	options := installedCache(t)
	var group sync.WaitGroup
	failures := make(chan error, 8)
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			db, err := OpenCached(options.CacheDir)
			if err != nil {
				failures <- err
				return
			}
			defer db.Close()
			if _, err := db.Lookup("172.20.0.1"); err != nil {
				failures <- err
			}
		}()
	}
	group.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}

func writeTestPointer(t *testing.T, cache, version string) {
	t.Helper()
	checksums := make(map[string]string)
	for _, name := range bundleFiles {
		checksums[name] = strings.Repeat("a", 64)
	}
	data := editJSON(t, []byte(`{}`), func(document map[string]any) {
		document["version"] = version
		document["checksums"] = checksums
	})
	if err := os.WriteFile(filepath.Join(cache, pointerFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOpenWithRetryFollowsMovedPointer(t *testing.T) {
	cache := t.TempDir()
	first, second := strings.Repeat("1", 64), strings.Repeat("2", 64)
	writeTestPointer(t, cache, first)
	var versions []string
	db, err := openWithRetry(cache, func(directory string, _ map[string]string) (*Database, error) {
		versions = append(versions, filepath.Base(directory))
		if len(versions) == 1 {
			writeTestPointer(t, cache, second)
			return nil, os.ErrNotExist
		}
		return &Database{}, nil
	})
	if err != nil || db == nil {
		t.Fatalf("retry failed: %v", err)
	}
	if len(versions) != 2 || versions[0] != first || versions[1] != second {
		t.Fatalf("attempted versions: %v", versions)
	}
}

func TestOpenWithRetryStopsWhenPointerIsUnchanged(t *testing.T) {
	cache := t.TempDir()
	writeTestPointer(t, cache, strings.Repeat("1", 64))
	calls := 0
	_, err := openWithRetry(cache, func(string, map[string]string) (*Database, error) {
		calls++
		return nil, ErrChecksumMismatch
	})
	if !errors.Is(err, ErrChecksumMismatch) || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestOpenWithRetryIsBounded(t *testing.T) {
	cache := t.TempDir()
	writeTestPointer(t, cache, strings.Repeat("0", 64))
	calls := 0
	_, err := openWithRetry(cache, func(string, map[string]string) (*Database, error) {
		calls++
		writeTestPointer(t, cache, strings.Repeat(string(rune('0'+calls)), 64))
		return nil, os.ErrNotExist
	})
	if !errors.Is(err, os.ErrNotExist) || calls != maxOpenAttempts {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestOpenWithRetryDoesNotRetryOtherErrors(t *testing.T) {
	cache := t.TempDir()
	writeTestPointer(t, cache, strings.Repeat("1", 64))
	calls := 0
	_, err := openWithRetry(cache, func(string, map[string]string) (*Database, error) {
		calls++
		writeTestPointer(t, cache, strings.Repeat("2", 64))
		return nil, ErrInvalidBundle
	})
	if !errors.Is(err, ErrInvalidBundle) || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestVersionIsContentAddressed(t *testing.T) {
	checksums := make(map[string]string)
	for name, data := range fixtureFiles(t) {
		checksums[name] = checksum(data)
	}
	version, err := versionOf(checksums)
	if err != nil || version != fixtureVersion {
		t.Fatalf("version %q, %v", version, err)
	}
}
