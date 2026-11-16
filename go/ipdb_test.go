package ipdb

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/flock"
)

// fixtureVersion is the content-addressed version of the shared fixtures.
const fixtureVersion = "ac95640bbd1d1c9d3f75239dbf7fd242b0c5f8fb5aa5332480220c904a22c157"

func fixtureFiles(t *testing.T) map[string][]byte {
	t.Helper()
	files := make(map[string][]byte)
	for _, file := range bundleFiles {
		data, err := os.ReadFile(filepath.Join("testdata", file))
		if err != nil {
			t.Fatal(err)
		}
		files[file] = data
	}
	return files
}

// copyBundle writes the fixtures, after mutate edited them, to a new directory.
func copyBundle(t *testing.T, mutate func(files map[string][]byte)) string {
	t.Helper()
	files := fixtureFiles(t)
	mutate(files)
	directory := t.TempDir()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}

// editJSON decodes a JSON object, applies edit and encodes it again.
func editJSON(t *testing.T, data []byte, edit func(document map[string]any)) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	edit(document)
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func fixtureServer(t *testing.T, files map[string][]byte, requests *int, failure *string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*requests++
		file := strings.TrimPrefix(r.URL.Path, "/")
		if file == *failure {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if file == "checksums.json" {
			checksums := make(map[string]string)
			for name, data := range files {
				checksums[name] = checksum(data)
			}
			if *failure == "checksum" {
				checksums["DN42-IPDB-City.mmdb"] = strings.Repeat("0", 64)
			}
			if err := json.NewEncoder(w).Encode(checksums); err != nil {
				t.Error(err)
			}
			return
		}
		data, found := files[file]
		if !found {
			http.NotFound(w, r)
			return
		}
		if _, err := w.Write(data); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// installedCache downloads the fixtures into a new cache and returns its options.
func installedCache(t *testing.T) DownloadOptions {
	t.Helper()
	requests, failure := 0, ""
	server := fixtureServer(t, fixtureFiles(t), &requests, &failure)
	options := DownloadOptions{CacheDir: t.TempDir(), BaseURL: server.URL}
	result, err := Download(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if err := result.Database.Close(); err != nil {
		t.Fatal(err)
	}
	return options
}

func TestLocalLookup(t *testing.T) {
	db, err := Open("testdata")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, ip := range []string{"172.20.0.1", "fd42:1234::1"} {
		result, err := db.Lookup(ip)
		if err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(result.Records["asn"].Data["autonomous_system_number"]) != "4242420001" {
			t.Fatalf("ASN lookup: %#v", result)
		}
		if len(result.Records) != 4 {
			t.Fatalf("missing records: %#v", result)
		}
	}
	info, found := db.LookupASN(4242420001)
	if !found || info.ASN != 4242420001 || info.AsName == nil || *info.AsName != "TestNetwork" {
		t.Fatalf("ASN index record: %#v %v", info, found)
	}
	if len(info.Observations) == 0 || len(info.RegisteredCountries) != 1 || info.RegisteredCountries[0].ISOCode != "DE" {
		t.Fatalf("typed ASN record: %#v", info)
	}
	if _, found := db.LookupASN(4242420999); found {
		t.Fatal("unexpected ASN index record")
	}
	missing, err := db.Lookup("203.0.113.1")
	if err != nil || len(missing.Records) != 0 {
		t.Fatalf("missing lookup: %v %#v", err, missing)
	}
	if _, err := db.Lookup("bad-ip"); !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("invalid IP accepted: %v", err)
	}
	if len(db.Metadata()) != 4 {
		t.Fatal("missing metadata")
	}
	release := db.ReleaseMetadata()
	if !strings.Contains(release.ReleaseRepository, "DN42-IPDB-Releases") || release.SchemaVersion != "2" || release.Raw["generator"] != "DN42-IPDB" {
		t.Fatalf("release metadata: %#v", release)
	}
}

func TestDownloadReuseAndFailures(t *testing.T) {
	files := fixtureFiles(t)
	requests, failure := 0, ""
	server := fixtureServer(t, files, &requests, &failure)
	options := DownloadOptions{CacheDir: t.TempDir(), BaseURL: server.URL}
	first, err := Download(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if !first.Changed || requests != 8 {
		t.Fatalf("first install: %#v requests=%d", first, requests)
	}
	_ = first.Database.Close()
	second, err := Download(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed || second.Directory != first.Directory || requests != 9 {
		t.Fatalf("cache reuse: %#v requests=%d", second, requests)
	}
	_ = second.Database.Close()
	db, err := OpenCached(options.CacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := db.LookupASN(4242420001); !found {
		t.Fatal("cached index missing")
	}
	_ = db.Close()
	if requests != 9 {
		t.Fatal("local lookup made a request")
	}
	pointerPath := filepath.Join(cacheDirectory(options.CacheDir), "current.json")
	original, err := os.ReadFile(pointerPath)
	if err != nil {
		t.Fatal(err)
	}
	files["metadata.json"] = []byte(`{"schema_version":"2","release_repository":"test","copyright":"BIRDCC","revision":1}`)
	failure = "DN42-IPDB-ASN.mmdb"
	if _, err := Download(context.Background(), options); !errors.Is(err, ErrHTTPStatus) {
		t.Fatalf("partial download accepted: %v", err)
	}
	failure = ""
	files["DN42-IPDB-City.mmdb"] = files["DN42-IPDB-ASN.mmdb"]
	if _, err := Download(context.Background(), options); !errors.Is(err, ErrInvalidBundle) || !strings.Contains(err.Error(), "City") {
		t.Fatalf("wrong database accepted: %v", err)
	}
	failure = "checksum"
	if _, err := Download(context.Background(), options); !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("wrong checksum accepted: %v", err)
	}
	current, err := os.ReadFile(pointerPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(original) {
		t.Fatal("failed update changed pointer")
	}
}

func TestCancellation(t *testing.T) {
	files := fixtureFiles(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/checksums.json" {
			checksums := make(map[string]string)
			for name, data := range files {
				checksums[name] = checksum(data)
			}
			_ = json.NewEncoder(w).Encode(checksums)
			return
		}
		<-r.Context().Done()
	}))
	defer server.Close()
	cache := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := Download(ctx, DownloadOptions{CacheDir: cache, BaseURL: server.URL}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(cacheDirectory(cache), "current.json")); !os.IsNotExist(err) {
		t.Fatalf("unexpected pointer: %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	if _, err := Download(ctx, DownloadOptions{CacheDir: cache, BaseURL: server.URL, Timeout: time.Minute}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation error, got %v", err)
	}
}

func TestRetentionAndIndependentReaders(t *testing.T) {
	files := fixtureFiles(t)
	requests, failure := 0, ""
	server := fixtureServer(t, files, &requests, &failure)
	options := DownloadOptions{CacheDir: t.TempDir(), BaseURL: server.URL}
	first, err := Download(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Database.Close()
	db, err := OpenCached(options.CacheDir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	custom := filepath.Join(cacheDirectory(options.CacheDir), strings.Repeat("f", 64))
	if err := os.Mkdir(custom, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(custom, "user.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	for revision := 1; revision <= 3; revision++ {
		files["metadata.json"] = []byte(fmt.Sprintf(`{"schema_version":"2","release_repository":"test","copyright":"BIRDCC","revision":%d}`, revision))
		update, err := Download(context.Background(), options)
		if err != nil {
			t.Fatal(err)
		}
		_ = update.Database.Close()
	}
	entries, err := os.ReadDir(cacheDirectory(options.CacheDir))
	if err != nil {
		t.Fatal(err)
	}
	versions := 0
	for _, entry := range entries {
		if entry.IsDir() && digestPattern.MatchString(entry.Name()) {
			versions++
		}
	}
	if versions != 3 {
		t.Fatalf("expected two owned versions and custom directory, got %d", versions)
	}
	if _, err := os.Stat(first.Directory); !os.IsNotExist(err) {
		t.Fatal("first version retained")
	}
	if _, err := os.Stat(filepath.Join(custom, "user.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Lookup("172.20.0.1"); err != nil {
		t.Fatal(err)
	}
}

func TestHoldCacheLock(t *testing.T) {
	cache := os.Getenv("DN42_LOCK_CACHE")
	if cache == "" {
		t.Skip("subprocess helper")
	}
	guard := flock.New(filepath.Join(cache, ".update.lock"))
	if err := guard.Lock(); err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	fmt.Println("locked")
	_, _ = bufio.NewReader(os.Stdin).ReadByte()
}

func TestCrossProcessLock(t *testing.T) {
	files := fixtureFiles(t)
	requests, failure := 0, ""
	server := fixtureServer(t, files, &requests, &failure)
	options := DownloadOptions{CacheDir: t.TempDir(), BaseURL: server.URL, Timeout: 100 * time.Millisecond}
	first, err := Download(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	_ = first.Database.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestHoldCacheLock$")
	child.Env = append(os.Environ(), "DN42_LOCK_CACHE="+cacheDirectory(options.CacheDir))
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = stdin.Close()
		if err := child.Wait(); err != nil {
			t.Error(err)
		}
	}()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "locked\n" {
		t.Fatalf("child lock: %q %v", line, err)
	}
	reader, err := OpenCached(options.CacheDir)
	if err != nil {
		t.Fatalf("readers must not take the writer lock: %v", err)
	}
	_ = reader.Close()
	if _, err := Download(context.Background(), options); !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("download ignored lock: %v", err)
	}
}

func TestV2CacheInitialization(t *testing.T) {
	files := fixtureFiles(t)
	requests, failure := 0, ""
	server := fixtureServer(t, files, &requests, &failure)
	options := DownloadOptions{CacheDir: t.TempDir(), BaseURL: server.URL}
	language := filepath.Join(options.CacheDir, "go")
	if err := os.MkdirAll(language, 0o700); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(language, "current.json")
	if err := os.WriteFile(existing, []byte("existing cache layout"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Download(context.Background(), options)
	if err != nil || !result.Changed || filepath.Dir(result.Directory) != filepath.Join(language, "v2") {
		t.Fatalf("v2 activation: %#v, %v", result, err)
	}
	_ = result.Database.Close()
	data, err := os.ReadFile(existing)
	if err != nil || string(data) != "existing cache layout" {
		t.Fatalf("existing cache: %q, %v", data, err)
	}
	db, err := OpenCached(options.CacheDir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, found := db.LookupASN(4242420001); !found {
		t.Fatal("new cache index missing")
	}
}

func TestRecoverMalformedPointer(t *testing.T) {
	options := installedCache(t)
	pointerPath := filepath.Join(cacheDirectory(options.CacheDir), "current.json")
	if err := os.WriteFile(pointerPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Download(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Database.Close()
	if !result.Changed || !result.RecoveredCache {
		t.Fatalf("cache recovery was not reported: %#v", result)
	}
	db, err := OpenCached(options.CacheDir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, found := db.LookupASN(4242420001); !found {
		t.Fatal("recovered cache index missing")
	}
}
