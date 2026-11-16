package ipdb

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/flock"
)

func TestDownloadContentAddressedAndHealing(t *testing.T) {
	requests, failure := 0, ""
	files := fixtureFiles(t)
	server := fixtureServer(t, files, &requests, &failure)
	options := DownloadOptions{CacheDir: t.TempDir(), BaseURL: server.URL}
	first, err := Download(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Changed || first.RecoveredCache || filepath.Base(first.Directory) != fixtureVersion {
		t.Fatalf("first install: %#v", first)
	}
	if result, err := first.Database.Lookup("172.20.0.1"); err != nil || len(result.Records) != 4 {
		t.Fatalf("downloaded bundle: %#v %v", result, err)
	}
	_ = first.Database.Close()
	second, err := Download(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed || second.RecoveredCache || second.Directory != first.Directory || second.Database == nil {
		t.Fatalf("second download: %#v", second)
	}
	_ = second.Database.Close()

	target := filepath.Join(first.Directory, "DN42-IPDB-City.mmdb")
	if err := os.WriteFile(target, []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	healed, err := Download(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if !healed.Changed || !healed.RecoveredCache || healed.Directory != first.Directory {
		t.Fatalf("damaged file: %#v", healed)
	}
	_ = healed.Database.Close()
	data, err := os.ReadFile(target)
	if err != nil || string(data) != string(files["DN42-IPDB-City.mmdb"]) {
		t.Fatalf("cache was not healed: %v", err)
	}
	cached, err := OpenCached(options.CacheDir)
	if err != nil {
		t.Fatal(err)
	}
	_ = cached.Close()

	if err := os.Remove(filepath.Join(first.Directory, licenseFile)); err != nil {
		t.Fatal(err)
	}
	missing, err := Download(context.Background(), options)
	if err != nil || !missing.Changed || !missing.RecoveredCache {
		t.Fatalf("missing file: %#v %v", missing, err)
	}
	_ = missing.Database.Close()
}

func TestDownloadRecoversCorruptPointer(t *testing.T) {
	for name, content := range map[string]string{
		"invalid json":   "{",
		"wrong shape":    `[]`,
		"bad digests":    `{"version":"x","checksums":{}}`,
		"missing digest": `{"version":"` + fixtureVersion + `","checksums":{}}`,
		"oversized":      strings.Repeat(" ", MaxManifestBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			options := installedCache(t)
			if err := os.WriteFile(filepath.Join(cacheDirectory(options.CacheDir), pointerFile), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := Download(context.Background(), options)
			if err != nil {
				t.Fatal(err)
			}
			defer result.Database.Close()
			if !result.Changed || !result.RecoveredCache {
				t.Fatalf("recovery: %#v", result)
			}
			if _, err := OpenCached(options.CacheDir); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDownloadModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	options := installedCache(t)
	cache := cacheDirectory(options.CacheDir)
	for path, want := range map[string]os.FileMode{
		cache:                                0o700,
		filepath.Join(cache, fixtureVersion): 0o700,
		filepath.Join(cache, pointerFile):    0o600,
		filepath.Join(cache, fixtureVersion, "metadata.json"): 0o600,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != want {
			t.Errorf("%s: mode %v, want %v", path, info.Mode().Perm(), want)
		}
	}
}

// TestDownloadWithReadersHoldingFiles keeps files of the oldest version and
// current.json open while a download of a third release starts; the download
// finishes once the files are closed and prunes the oldest version.
func TestDownloadWithReadersHoldingFiles(t *testing.T) {
	files := fixtureFiles(t)
	requests, failure := 0, ""
	server := fixtureServer(t, files, &requests, &failure)
	options := DownloadOptions{CacheDir: t.TempDir(), BaseURL: server.URL, Timeout: 20 * time.Second}
	var versions []string
	for _, tag := range []string{"first", "second"} {
		files[metadataFile] = editJSON(t, files[metadataFile], func(d map[string]any) { d["release_tag"] = tag })
		result, err := Download(context.Background(), options)
		if err != nil {
			t.Fatal(err)
		}
		_ = result.Database.Close()
		versions = append(versions, result.Directory)
	}
	oldest := versions[0]
	held := []*os.File{}
	for _, path := range []string{
		filepath.Join(oldest, "DN42-IPDB-City.mmdb"),
		filepath.Join(cacheDirectory(options.CacheDir), pointerFile),
	} {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, file)
	}
	files[metadataFile] = editJSON(t, files[metadataFile], func(d map[string]any) { d["release_tag"] = "third" })
	done := make(chan error, 1)
	go func() {
		result, err := Download(context.Background(), options)
		if err == nil {
			err = result.Database.Close()
		}
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)
	for _, file := range held {
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldest); !os.IsNotExist(err) {
		t.Fatalf("oldest version was not pruned: %v", err)
	}
	if _, err := os.Stat(versions[1]); err != nil {
		t.Fatalf("previous version missing: %v", err)
	}
}

func TestRetryWhileDenied(t *testing.T) {
	previous := retryOnDenied
	retryOnDenied = true
	defer func() { retryOnDenied = previous }()
	attempts := 0
	err := retryWhileDenied(context.Background(), func() error {
		attempts++
		if attempts < 3 {
			return &os.LinkError{Op: "rename", Err: errorAccessDenied}
		}
		return nil
	})
	if err != nil || attempts != 3 {
		t.Fatalf("attempts %d: %v", attempts, err)
	}
	other := errors.New("other failure")
	if err := retryWhileDenied(context.Background(), func() error { return other }); !errors.Is(err, other) {
		t.Fatalf("other errors must return at once: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	err = retryWhileDenied(ctx, func() error { return errorSharingViolation })
	if !errors.Is(err, errorSharingViolation) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline must end the retries: %v", err)
	}
	retryOnDenied = false
	attempts = 0
	if err := retryWhileDenied(context.Background(), func() error { attempts++; return errorAccessDenied }); err == nil || attempts != 1 {
		t.Fatalf("retries must be off: %d %v", attempts, err)
	}
}

func TestDownloadWaitsForWriterLock(t *testing.T) {
	requests, failure := 0, ""
	server := fixtureServer(t, fixtureFiles(t), &requests, &failure)
	options := DownloadOptions{CacheDir: t.TempDir(), BaseURL: server.URL, Timeout: 10 * time.Second}
	cache := cacheDirectory(options.CacheDir)
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	guard := flock.New(filepath.Join(cache, lockFile))
	if err := guard.Lock(); err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	time.AfterFunc(300*time.Millisecond, func() {
		_ = guard.Unlock()
		close(released)
	})
	started := time.Now()
	result, err := Download(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Database.Close()
	<-released
	if time.Since(started) < 250*time.Millisecond || !result.Changed {
		t.Fatalf("download did not wait for the lock: %v %#v", time.Since(started), result)
	}
}

func TestDownloadLockTimeout(t *testing.T) {
	requests, failure := 0, ""
	server := fixtureServer(t, fixtureFiles(t), &requests, &failure)
	options := DownloadOptions{CacheDir: t.TempDir(), BaseURL: server.URL, Timeout: 150 * time.Millisecond}
	cache := cacheDirectory(options.CacheDir)
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	guard := flock.New(filepath.Join(cache, lockFile))
	if err := guard.Lock(); err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	if _, err := Download(context.Background(), options); !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("expected lock-timeout error, got %v", err)
	}
	if requests != 0 {
		t.Fatal("download contacted the server before taking the lock")
	}
}

func TestDownloadPrunesLeftovers(t *testing.T) {
	requests, failure := 0, ""
	files := fixtureFiles(t)
	server := fixtureServer(t, files, &requests, &failure)
	options := DownloadOptions{CacheDir: t.TempDir(), BaseURL: server.URL}
	first, err := Download(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Database.Close()
	cache := cacheDirectory(options.CacheDir)
	if err := os.MkdirAll(filepath.Join(cache, ".stage-x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, ".stage-x", "partial"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, ".current-x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(cache, "unknown-directory")
	if err := os.Mkdir(unknown, 0o700); err != nil {
		t.Fatal(err)
	}
	files["metadata.json"] = editJSON(t, files["metadata.json"], func(d map[string]any) { d["release_tag"] = "next" })
	update, err := Download(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	_ = update.Database.Close()
	for _, name := range []string{".stage-x", ".current-x"} {
		if _, err := os.Stat(filepath.Join(cache, name)); !os.IsNotExist(err) {
			t.Errorf("%s was not removed: %v", name, err)
		}
	}
	if _, err := os.Stat(unknown); err != nil {
		t.Errorf("unknown directory removed: %v", err)
	}
	entries, err := os.ReadDir(cache)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".stage-") || strings.HasPrefix(entry.Name(), ".current-") {
			t.Errorf("temporary entry left behind: %s", entry.Name())
		}
	}
}

func TestBaseURLValidation(t *testing.T) {
	for _, raw := range []string{
		"https://user:secret@example.com/",
		"https://@example.com/",
		"https://example.com/?token=1",
		"https://example.com/?",
		"https://example.com/#fragment",
		"https://example.com/#",
		"http://example.com/",
		"http://localhost/",
		"http://[::2]/",
		"http://[::ffff:127.0.0.1]/",
		"http://[::ffff:7f00:1]/",
		"https://@example.com",
		"https://example.com?",
		"ftp://example.com/",
		"https:///path",
		"://bad",
	} {
		if _, err := Download(context.Background(), DownloadOptions{CacheDir: t.TempDir(), BaseURL: raw}); !errors.Is(err, ErrInvalidURL) {
			t.Errorf("%q: %v", raw, err)
		}
	}
	for raw, want := range map[string]string{
		"http://127.0.0.2/":              "http://127.0.0.2/",
		"http://[::1]:8080/releases":     "http://[::1]:8080/releases/",
		"https://example.com/releases/":  "https://example.com/releases/",
		"https://example.com":            "https://example.com/",
		"https://[2001:db8::1]/download": "https://[2001:db8::1]/download/",
	} {
		parsed, err := parseBaseURL(raw)
		if err != nil || parsed.String() != want {
			t.Errorf("%q: %v %v", raw, parsed, err)
		}
	}
}

func TestDownloadRejectsNegativeTimeout(t *testing.T) {
	if _, err := Download(context.Background(), DownloadOptions{CacheDir: t.TempDir(), Timeout: -time.Second}); err == nil {
		t.Fatal("negative timeout accepted")
	}
}

func redirectServer(t *testing.T, target func(r *http.Request) string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target(r), http.StatusFound)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestRedirectPolicy(t *testing.T) {
	for name, target := range map[string]func(r *http.Request) string{
		"insecure host":     func(*http.Request) string { return "http://example.com/checksums.json" },
		"other loopback":    func(*http.Request) string { return "http://127.0.0.2:1/checksums.json" },
		"credentials":       func(*http.Request) string { return "https://user:secret@example.com/checksums.json" },
		"empty user info":   func(*http.Request) string { return "https://@example.com/checksums.json" },
		"fragment":          func(*http.Request) string { return "https://example.com/checksums.json#top" },
		"empty fragment":    func(*http.Request) string { return "https://example.com/checksums.json#" },
		"unparsable":        func(*http.Request) string { return "http://[::1/checksums.json" },
		"mapped loopback":   func(*http.Request) string { return "http://[::ffff:127.0.0.1]:1/checksums.json" },
		"unsupported":       func(*http.Request) string { return "ftp://example.com/checksums.json" },
		"too many redirect": func(r *http.Request) string { return r.URL.Path + "x" },
	} {
		t.Run(name, func(t *testing.T) {
			server := redirectServer(t, target)
			_, err := Download(context.Background(), DownloadOptions{CacheDir: t.TempDir(), BaseURL: server.URL})
			if !errors.Is(err, ErrInvalidURL) {
				t.Fatalf("expected invalid-url error, got %v", err)
			}
		})
	}
}

func TestRedirectWithoutLocation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	_, err := Download(context.Background(), DownloadOptions{CacheDir: t.TempDir(), BaseURL: server.URL})
	if !errors.Is(err, ErrInvalidURL) || errors.Is(err, ErrHTTPStatus) {
		t.Fatalf("expected invalid-url error, got %v", err)
	}
}

func TestRedirectWithinLoopbackHost(t *testing.T) {
	files := fixtureFiles(t)
	requests, failure := 0, ""
	inner := fixtureServer(t, files, &requests, &failure)
	outer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, inner.URL+strings.TrimPrefix(r.URL.Path, "/start"), http.StatusFound)
	}))
	defer outer.Close()
	// Same loopback host but another port is a different origin and is refused.
	if _, err := Download(context.Background(), DownloadOptions{CacheDir: t.TempDir(), BaseURL: outer.URL + "/start"}); !errors.Is(err, ErrInvalidURL) {
		t.Fatalf("cross-port redirect: %v", err)
	}
	same := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/start/") {
			http.Redirect(w, r, strings.TrimPrefix(r.URL.Path, "/start"), http.StatusFound)
			return
		}
		inner.Config.Handler.ServeHTTP(w, r)
	}))
	defer same.Close()
	result, err := Download(context.Background(), DownloadOptions{CacheDir: t.TempDir(), BaseURL: same.URL + "/start"})
	if err != nil {
		t.Fatal(err)
	}
	_ = result.Database.Close()
}

func TestRedirectMayCarryQuery(t *testing.T) {
	files := fixtureFiles(t)
	requests, failure := 0, ""
	inner := fixtureServer(t, files, &requests, &failure)
	queries := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery == "" {
			http.Redirect(w, r, r.URL.Path+"?signature=abc", http.StatusFound)
			return
		}
		queries++
		inner.Config.Handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	result, err := Download(context.Background(), DownloadOptions{CacheDir: t.TempDir(), BaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	_ = result.Database.Close()
	if queries != len(bundleFiles)+1 {
		t.Fatalf("signed requests: %d", queries)
	}
}

func TestDownloadHTTPStatusAndSizeLimit(t *testing.T) {
	requests, failure := 0, "checksums.json"
	server := fixtureServer(t, fixtureFiles(t), &requests, &failure)
	_, err := Download(context.Background(), DownloadOptions{CacheDir: t.TempDir(), BaseURL: server.URL})
	if !errors.Is(err, ErrHTTPStatus) || !strings.Contains(err.Error(), "503") || !strings.Contains(err.Error(), "checksums.json") {
		t.Fatalf("expected http-status error with URL and status, got %v", err)
	}
	for name, chunked := range map[string]bool{"content length": false, "streamed": true} {
		t.Run(name, func(t *testing.T) {
			oversized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body := []byte(strings.Repeat("x", MaxManifestBytes+1))
				if chunked {
					w.(http.Flusher).Flush()
				}
				_, _ = w.Write(body)
			}))
			defer oversized.Close()
			_, err := Download(context.Background(), DownloadOptions{CacheDir: t.TempDir(), BaseURL: oversized.URL})
			if !errors.Is(err, ErrSizeLimit) {
				t.Fatalf("expected size-limit error, got %v", err)
			}
		})
	}
}

func TestDownloadRejectsInvalidManifest(t *testing.T) {
	for name, body := range map[string]string{
		"not json":       "{",
		"not an object":  `[]`,
		"missing digest": `{}`,
		"short digest":   `{"metadata.json":"abc"}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			_, err := Download(context.Background(), DownloadOptions{CacheDir: t.TempDir(), BaseURL: server.URL})
			if !errors.Is(err, ErrInvalidBundle) || !strings.Contains(err.Error(), manifestFile) {
				t.Fatalf("expected invalid-bundle error naming the manifest, got %v", err)
			}
		})
	}
}

func TestManifestIgnoresOtherKeys(t *testing.T) {
	checksums := make(map[string]string)
	for name, data := range fixtureFiles(t) {
		checksums[name] = checksum(data)
	}
	data := editJSON(t, []byte(`{}`), func(d map[string]any) {
		for name, digest := range checksums {
			d[name] = digest
		}
		d["extra"] = 7
	})
	parsed, err := parseChecksums(data)
	if err != nil || len(parsed) != len(bundleFiles) {
		t.Fatalf("%v %v", parsed, err)
	}
}
