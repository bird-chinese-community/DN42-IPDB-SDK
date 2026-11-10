use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use dn42_ipdb::{Bundle, Cache, Cancellation, Error};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tiny_http::{Header, Response, Server, StatusCode};

const FILES: [&str; 7] = [
    "country.mmdb",
    "city.mmdb",
    "asn.mmdb",
    "connection-type.mmdb",
    "asn-index.json",
    "metadata.json",
    "LICENSE-Unicode.txt",
];

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}

fn fixture_copy() -> TempDir {
    let directory = tempfile::tempdir().unwrap();
    for name in FILES {
        fs::copy(fixtures().join(name), directory.path().join(name)).unwrap();
    }
    directory
}

#[derive(Default)]
struct State {
    revision: u32,
    corrupt_city: bool,
    wrong_asn_type: bool,
    missing_file: Option<String>,
    redirect_city: bool,
    cancel_city: Option<Cancellation>,
    block_pointer: Option<PathBuf>,
}

struct ReleaseServer {
    url: String,
    state: Arc<Mutex<State>>,
    calls: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl ReleaseServer {
    fn start() -> Self {
        let server = Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", server.server_addr());
        let state = Arc::new(Mutex::new(State::default()));
        let calls = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_state = state.clone();
        let thread_calls = calls.clone();
        let thread_stop = stop.clone();
        let worker = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                let Some(request) = server.recv_timeout(Duration::from_millis(20)).unwrap() else {
                    continue;
                };
                thread_calls.fetch_add(1, Ordering::Relaxed);
                let state = thread_state.lock().unwrap();
                let mut data: BTreeMap<_, _> = FILES
                    .iter()
                    .map(|name| (*name, fs::read(fixtures().join(name)).unwrap()))
                    .collect();
                let mut metadata: Value = serde_json::from_slice(&data["metadata.json"]).unwrap();
                metadata["test_revision"] = json!(state.revision);
                data.insert("metadata.json", serde_json::to_vec(&metadata).unwrap());
                if state.wrong_asn_type {
                    data.insert("asn.mmdb", data["country.mmdb"].clone());
                }
                let hashes: BTreeMap<_, _> = data
                    .iter()
                    .map(|(name, bytes)| (*name, format!("{:x}", Sha256::digest(bytes))))
                    .collect();
                let name = request.url().trim_start_matches('/');
                if name == "metadata.json"
                    && let Some(pointer) = &state.block_pointer
                {
                    fs::remove_file(pointer).unwrap();
                    fs::create_dir(pointer).unwrap();
                }
                if name == "city.mmdb" {
                    if let Some(cancellation) = &state.cancel_city {
                        cancellation.cancel();
                    }
                    if state.redirect_city {
                        request
                            .respond(
                                Response::empty(StatusCode(302)).with_header(
                                    Header::from_bytes("Location", "http://192.0.2.1/blocked.mmdb")
                                        .unwrap(),
                                ),
                            )
                            .unwrap();
                        continue;
                    }
                }
                if state.missing_file.as_deref() == Some(name) {
                    request.respond(Response::empty(StatusCode(404))).unwrap();
                } else if name == "checksums.json" {
                    request
                        .respond(Response::from_data(serde_json::to_vec(&hashes).unwrap()))
                        .unwrap();
                } else if let Some(bytes) = data.get(name) {
                    let bytes = if name == "city.mmdb" && state.corrupt_city {
                        b"corrupt".to_vec()
                    } else {
                        bytes.clone()
                    };
                    let result = request.respond(Response::from_data(bytes));
                    if let Err(error) = result {
                        assert!(matches!(
                            error.kind(),
                            io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                        ));
                    }
                } else {
                    request.respond(Response::empty(StatusCode(404))).unwrap();
                }
            }
        });
        Self {
            url,
            state,
            calls,
            stop,
            thread: Some(worker),
        }
    }
}

impl Drop for ReleaseServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.thread.take().unwrap().join().unwrap();
    }
}

#[test]
fn reads_ipv4_ipv6_and_asn_contract() {
    let bundle = Bundle::open(fixtures()).unwrap();
    for ip in ["172.20.0.1", "fd42:1234::1"] {
        let result = bundle.lookup_ip(ip.parse().unwrap()).unwrap();
        assert_eq!(result.records.len(), 4);
        let data = &result.records["city"].data;
        assert_eq!(data["country"]["iso_code"], "US");
        assert_eq!(data["country"]["names"]["en"], "United States");
        assert_eq!(data["subdivisions"][0]["names"]["en"], "California");
        assert_eq!(data["city"]["names"]["en"], "Test City");
        assert_eq!(data["dn42"]["schema_version"], "2");
        assert_eq!(data["dn42"]["roa_status"], "valid");
        assert_eq!(data["dn42"]["irr_status"], "exact");
        assert!(
            data["dn42"]["network_types"]
                .as_array()
                .unwrap()
                .contains(&json!("anycast"))
        );
        assert!(!data["dn42"]["observations"].as_array().unwrap().is_empty());
    }
    let asn = bundle.lookup_asn(4_242_420_001).unwrap();
    assert_eq!(asn.as_name.as_deref(), Some("TestNetwork"));
    assert_eq!(asn.registered_countries[0].names["en"], "Germany");
    assert!(
        asn.observed_network_types
            .contains(&"public-resolver".to_string())
    );
    assert!(bundle.lookup_asn(1).is_none());
    assert!(
        bundle
            .lookup_ip("203.0.113.1".parse().unwrap())
            .unwrap()
            .records
            .is_empty()
    );
    let mapped = bundle
        .lookup_ip("::ffff:172.20.0.1".parse().unwrap())
        .unwrap();
    assert_eq!(mapped.ip, "172.20.0.1".parse::<IpAddr>().unwrap());
    assert!(
        bundle.release_metadata()["copyright"]
            .as_str()
            .unwrap()
            .contains("BIRD Chinese Community")
    );
}

#[test]
fn rejects_wrong_database_and_sidecar_schema() {
    let directory = fixture_copy();
    fs::copy(
        directory.path().join("country.mmdb"),
        directory.path().join("asn.mmdb"),
    )
    .unwrap();
    assert!(Bundle::open(directory.path()).is_err());
    let directory = fixture_copy();
    fs::write(
        directory.path().join("asn-index.json"),
        br#"{"schema_version":"1","asns":{}}"#,
    )
    .unwrap();
    assert!(Bundle::open(directory.path()).is_err());
    let directory = fixture_copy();
    fs::write(
        directory.path().join("metadata.json"),
        br#"{"schema_version":"2"}"#,
    )
    .unwrap();
    assert!(Bundle::open(directory.path()).is_err());
}

#[test]
fn explicit_download_and_cached_open_reuse_verified_bundle() {
    let server = ReleaseServer::start();
    let root = tempfile::tempdir().unwrap();
    let cache = Cache::with_url(root.path(), &server.url).unwrap();
    let update = cache.refresh().unwrap();
    assert!(update.changed);
    assert_eq!(server.calls.load(Ordering::Relaxed), 8);
    assert_eq!(
        update.bundle.lookup_asn(4_242_420_001).unwrap().asn,
        4_242_420_001
    );
    let cached = cache.open_cached().unwrap();
    assert!(
        !cached
            .lookup_ip("172.20.0.1".parse().unwrap())
            .unwrap()
            .records
            .is_empty()
    );
    assert_eq!(server.calls.load(Ordering::Relaxed), 8);
    assert!(!cache.refresh().unwrap().changed);
    assert_eq!(server.calls.load(Ordering::Relaxed), 9);
}

#[test]
fn failed_and_cancelled_downloads_preserve_the_active_pointer() {
    let server = ReleaseServer::start();
    let root = tempfile::tempdir().unwrap();
    let cache = Cache::with_url(root.path(), &server.url).unwrap();
    let initial = cache.refresh().unwrap();
    let pointer_path = root.path().join("rust/current.json");
    let pointer = fs::read(&pointer_path).unwrap();
    for mode in 0..5 {
        {
            let mut state = server.state.lock().unwrap();
            state.revision += 1;
            state.corrupt_city = mode == 0;
            state.wrong_asn_type = mode == 1;
            state.missing_file = (mode == 2).then(|| "asn.mmdb".to_string());
            state.redirect_city = mode == 3;
            state.cancel_city = None;
        }
        let cancellation = Cancellation::default();
        if mode == 4 {
            server.state.lock().unwrap().cancel_city = Some(cancellation.clone());
        }
        assert!(cache.refresh_with_cancel(&cancellation).is_err());
        assert_eq!(fs::read(&pointer_path).unwrap(), pointer);
        assert!(
            cache
                .open_cached()
                .unwrap()
                .lookup_asn(4_242_420_001)
                .is_some()
        );
    }
    assert!(initial.bundle.lookup_asn(4_242_420_001).is_some());
    let cancellation = Cancellation::default();
    cancellation.cancel();
    assert!(matches!(
        cache.refresh_with_cancel(&cancellation),
        Err(Error::Cancelled)
    ));
    assert_eq!(fs::read(&pointer_path).unwrap(), pointer);
}

#[test]
fn failed_activation_removes_its_new_version_directory() {
    let server = ReleaseServer::start();
    let root = tempfile::tempdir().unwrap();
    let cache = Cache::with_url(root.path(), &server.url).unwrap();
    let initial = cache.refresh().unwrap();
    let pointer = root.path().join("rust/current.json");
    {
        let mut state = server.state.lock().unwrap();
        state.revision = 1;
        state.block_pointer = Some(pointer.clone());
    }
    assert!(cache.refresh().is_err());
    assert!(pointer.is_dir());
    assert!(initial.directory.is_dir());
    assert!(initial.bundle.lookup_asn(4_242_420_001).is_some());
    let directories: Vec<_> = fs::read_dir(root.path().join("rust"))
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_type().unwrap().is_dir())
        .filter(|entry| entry.file_name().len() == 64)
        .collect();
    assert_eq!(directories.len(), 1);
}

#[test]
fn successive_updates_retain_two_bundles_and_preserve_custom_directories() {
    let server = ReleaseServer::start();
    let root = tempfile::tempdir().unwrap();
    let cache = Cache::with_url(root.path(), &server.url).unwrap();
    let initial = cache.refresh().unwrap();
    let custom = root.path().join("rust").join("a".repeat(64));
    fs::create_dir(&custom).unwrap();
    fs::write(custom.join("user.txt"), b"retain").unwrap();
    for revision in 1..4 {
        server.state.lock().unwrap().revision = revision;
        assert!(cache.refresh().unwrap().changed);
    }
    let owned = fs::read_dir(root.path().join("rust"))
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.unwrap();
            if !entry.file_type().unwrap().is_dir() {
                return None;
            }
            let contents: Vec<_> = fs::read_dir(entry.path()).unwrap().collect();
            (contents.len() == FILES.len()).then_some(entry.path())
        })
        .count();
    assert_eq!(owned, 2);
    assert!(!initial.directory.exists());
    assert!(initial.bundle.lookup_asn(4_242_420_001).is_some());
    assert_eq!(fs::read(custom.join("user.txt")).unwrap(), b"retain");
}

#[test]
fn lock_holder_helper() {
    let Ok(directory) = std::env::var("DN42_IPDB_LOCK_TEST_DIRECTORY") else {
        return;
    };
    let file = File::options()
        .read(true)
        .write(true)
        .open(Path::new(&directory).join(".update.lock"))
        .unwrap();
    file.lock().unwrap();
    fs::write(Path::new(&directory).join("lock-ready"), b"ready").unwrap();
    thread::sleep(Duration::from_secs(5));
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.0.kill().unwrap();
        self.0.wait().unwrap();
    }
}

#[test]
fn cached_reads_and_updates_obey_the_same_cross_process_lock() {
    let server = ReleaseServer::start();
    let root = tempfile::tempdir().unwrap();
    Cache::with_url(root.path(), &server.url)
        .unwrap()
        .refresh()
        .unwrap();
    let cache = Cache::with_url(root.path(), &server.url)
        .unwrap()
        .with_timeout(Duration::from_millis(100))
        .unwrap();
    let directory = root.path().join("rust");
    let _child = ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "lock_holder_helper", "--nocapture"])
            .env("DN42_IPDB_LOCK_TEST_DIRECTORY", &directory)
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    while !directory.join("lock-ready").exists() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    let calls = server.calls.load(Ordering::Relaxed);
    assert!(matches!(cache.open_cached(), Err(Error::Timeout)));
    assert!(matches!(cache.refresh(), Err(Error::Timeout)));
    assert_eq!(server.calls.load(Ordering::Relaxed), calls);
}

#[test]
fn rejects_insecure_release_origins() {
    let root = tempfile::tempdir().unwrap();
    assert!(Cache::with_url(root.path(), "http://192.0.2.1/").is_err());
    assert!(Cache::with_url(root.path(), "http://localhost/").is_err());
    assert!(Cache::with_url(root.path(), "https://user:secret@example.com/").is_err());
    assert!(Cache::with_url(root.path(), "https://example.com/?token=secret").is_err());
    assert!(Cache::with_url(root.path(), "http://[::1]:8080/").is_ok());
}
