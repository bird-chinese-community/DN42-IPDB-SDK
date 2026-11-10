package ipdb

import (
	"bufio"
	"context"
	"encoding/json"
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

func fixtureFiles(t *testing.T) map[string][]byte {
	t.Helper()
	files := make(map[string][]byte)
	for _, file := range artifactFiles() {
		data, err := os.ReadFile(filepath.Join("testdata", file))
		if err != nil {
			t.Fatal(err)
		}
		files[file] = data
	}
	return files
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
				checksums["city.mmdb"] = strings.Repeat("0", 64)
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
	if _, found := db.LookupASN(4242420001); !found {
		t.Fatal("missing ASN index record")
	}
	if _, found := db.LookupASN(4242420999); found {
		t.Fatal("unexpected ASN index record")
	}
	missing, err := db.Lookup("203.0.113.1")
	if err != nil || len(missing.Records) != 0 {
		t.Fatalf("missing lookup: %v %#v", err, missing)
	}
	if _, err := db.Lookup("bad-ip"); err == nil {
		t.Fatal("invalid IP accepted")
	}
	if len(db.Metadata()) != 4 {
		t.Fatal("missing metadata")
	}
	if !strings.Contains(fmt.Sprint(db.ReleaseMetadata()["release_repository"]), "DN42-IPDB-Releases") {
		t.Fatal("missing release repository")
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
	second, err := Download(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed || second.Directory != first.Directory || requests != 9 {
		t.Fatalf("cache reuse: %#v requests=%d", second, requests)
	}
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
	pointerPath := filepath.Join(options.CacheDir, "go", "current.json")
	original, err := os.ReadFile(pointerPath)
	if err != nil {
		t.Fatal(err)
	}
	files["metadata.json"] = []byte(`{"schema_version":"2","release_repository":"test","copyright":"BIRDCC","revision":1}`)
	failure = "asn.mmdb"
	if _, err := Download(context.Background(), options); err == nil {
		t.Fatal("partial download accepted")
	}
	failure = ""
	files["city.mmdb"] = files["asn.mmdb"]
	if _, err := Download(context.Background(), options); err == nil || !strings.Contains(err.Error(), "City") {
		t.Fatalf("wrong database accepted: %v", err)
	}
	failure = "checksum"
	if _, err := Download(context.Background(), options); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
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
	if _, err := Download(ctx, DownloadOptions{CacheDir: cache, BaseURL: server.URL}); err == nil {
		t.Fatal("cancelled download succeeded")
	}
	if _, err := os.Stat(filepath.Join(cache, "go", "current.json")); !os.IsNotExist(err) {
		t.Fatalf("unexpected pointer: %v", err)
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
	db, err := OpenCached(options.CacheDir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	custom := filepath.Join(options.CacheDir, "go", strings.Repeat("f", 64))
	if err := os.Mkdir(custom, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(custom, "user.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	for revision := 1; revision <= 3; revision++ {
		files["metadata.json"] = []byte(fmt.Sprintf(`{"schema_version":"2","release_repository":"test","copyright":"BIRDCC","revision":%d}`, revision))
		if _, err := Download(context.Background(), options); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(options.CacheDir, "go"))
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
	options := DownloadOptions{CacheDir: t.TempDir(), BaseURL: server.URL, Timeout: 50 * time.Millisecond}
	if _, err := Download(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestHoldCacheLock$")
	child.Env = append(os.Environ(), "DN42_LOCK_CACHE="+filepath.Join(options.CacheDir, "go"))
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
	if _, err := OpenCached(options.CacheDir); err == nil {
		t.Fatal("cached open ignored lock")
	}
	if _, err := Download(context.Background(), options); err == nil {
		t.Fatal("download ignored lock")
	}
}

func TestRecoverMalformedPointer(t *testing.T) {
	files := fixtureFiles(t)
	requests, failure := 0, ""
	server := fixtureServer(t, files, &requests, &failure)
	options := DownloadOptions{CacheDir: t.TempDir(), BaseURL: server.URL}
	if _, err := Download(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	pointerPath := filepath.Join(options.CacheDir, "go", "current.json")
	if err := os.WriteFile(pointerPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Download(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
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
