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

use dn42_ipdb::{Bundle, Cache, Cancellation, Error, FILES, MAX_MANIFEST_BYTES, Result, Update};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tiny_http::{Header, Response, Server, StatusCode};

const FIXTURE_VERSION: &str = "ac95640bbd1d1c9d3f75239dbf7fd242b0c5f8fb5aa5332480220c904a22c157";
const CITY: &str = "DN42-IPDB-City.mmdb";
const ASN_DB: &str = "DN42-IPDB-ASN.mmdb";

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

fn failure<T>(result: Result<T>) -> Error {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(error) => error,
    }
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

#[derive(Default)]
struct State {
    revision: u32,
    corrupt_city: bool,
    wrong_asn_type: bool,
    oversize_manifest: bool,
    missing_file: Option<String>,
    redirect_city: Option<String>,
    redirect_signed: bool,
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

fn release_files(state: &State) -> BTreeMap<&'static str, Vec<u8>> {
    let mut data: BTreeMap<_, _> = FILES
        .iter()
        .map(|name| (*name, fs::read(fixtures().join(name)).unwrap()))
        .collect();
    if state.revision > 0 {
        let mut metadata: Value = serde_json::from_slice(&data["metadata.json"]).unwrap();
        metadata["test_revision"] = json!(state.revision);
        data.insert("metadata.json", serde_json::to_vec(&metadata).unwrap());
    }
    if state.wrong_asn_type {
        data.insert(ASN_DB, data["DN42-IPDB-Country.mmdb"].clone());
    }
    data
}

fn respond(request: tiny_http::Request, state: &State, name: &str) {
    let data = release_files(state);
    if name == "metadata.json"
        && let Some(pointer) = &state.block_pointer
    {
        fs::remove_file(pointer).unwrap();
        fs::create_dir(pointer).unwrap();
    }
    if name == CITY {
        if let Some(cancellation) = &state.cancel_city {
            cancellation.cancel();
        }
        let signed = state.redirect_signed && !request.url().contains('?');
        let location = state
            .redirect_city
            .clone()
            .or_else(|| signed.then(|| format!("/{CITY}?signed=1")));
        if let Some(location) = location {
            let location = Header::from_bytes("Location", location).unwrap();
            request
                .respond(Response::empty(StatusCode(302)).with_header(location))
                .unwrap();
            return;
        }
    }
    if state.missing_file.as_deref() == Some(name) {
        request.respond(Response::empty(StatusCode(404))).unwrap();
    } else if name == "checksums.json" && state.oversize_manifest {
        let body = vec![b' '; MAX_MANIFEST_BYTES + 1];
        request.respond(Response::from_data(body)).unwrap();
    } else if name == "checksums.json" {
        let hashes: BTreeMap<_, _> = data
            .iter()
            .map(|(name, bytes)| (*name, format!("{:x}", Sha256::digest(bytes))))
            .collect();
        let body = serde_json::to_vec(&hashes).unwrap();
        request.respond(Response::from_data(body)).unwrap();
    } else if let Some(bytes) = data.get(name) {
        let bytes = if name == CITY && state.corrupt_city {
            b"corrupt".to_vec()
        } else {
            bytes.clone()
        };
        if let Err(error) = request.respond(Response::from_data(bytes)) {
            assert!(matches!(
                error.kind(),
                io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
            ));
        }
    } else {
        request.respond(Response::empty(StatusCode(404))).unwrap();
    }
}

impl ReleaseServer {
    fn start() -> Self {
        let server = Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", server.server_addr());
        let state = Arc::new(Mutex::new(State::default()));
        let calls = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (thread_state, thread_calls, thread_stop) =
            (state.clone(), calls.clone(), stop.clone());
        let worker = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                let Some(request) = server.recv_timeout(Duration::from_millis(20)).unwrap() else {
                    continue;
                };
                thread_calls.fetch_add(1, Ordering::Relaxed);
                let name = request
                    .url()
                    .trim_start_matches('/')
                    .split('?')
                    .next()
                    .unwrap()
                    .to_string();
                respond(request, &thread_state.lock().unwrap(), &name);
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

    fn cache(&self, root: &Path) -> Cache {
        Cache::with_url(root, &self.url).unwrap()
    }
}

impl Drop for ReleaseServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.thread.take().unwrap().join().unwrap();
    }
}

fn cache_directory(root: &Path) -> PathBuf {
    root.join("rust/v2")
}

fn assert_usable(bundle: &Bundle) {
    assert!(bundle.lookup_asn(4_242_420_001).is_some());
    assert!(
        !bundle
            .lookup_ip("172.20.0.1".parse().unwrap())
            .unwrap()
            .records
            .is_empty()
    );
}

#[test]
fn initializes_v2_beside_an_existing_language_cache() {
    let root = TempDir::new().unwrap();
    let language = root.path().join("rust");
    fs::create_dir_all(&language).unwrap();
    let existing = language.join("current.json");
    fs::write(&existing, "existing cache layout").unwrap();
    let server = ReleaseServer::start();
    let cache = server.cache(root.path());
    let update = cache.refresh().unwrap();
    assert!(update.changed);
    assert_eq!(update.directory.parent().unwrap(), language.join("v2"));
    assert_eq!(
        fs::read_to_string(existing).unwrap(),
        "existing cache layout"
    );
    assert_usable(&cache.open_cached().unwrap());
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
    assert!(
        bundle
            .release_metadata()
            .copyright
            .contains("BIRD Chinese Community")
    );
    assert_eq!(bundle.release_metadata().schema_version, "2");
}

#[test]
fn lookups_report_canonical_ip_and_masked_network() {
    let bundle = Bundle::open(fixtures()).unwrap();
    for input in ["::ffff:172.20.0.1", "::FFFF:AC14:1", "172.20.0.1"] {
        let result = bundle.lookup_ip(input.parse().unwrap()).unwrap();
        assert_eq!(result.ip.to_string(), "172.20.0.1", "{input}");
        assert_eq!(result.records.len(), 4);
        for found in result.records.values() {
            assert_eq!(found.network, "172.20.0.1/32");
            assert_eq!(found.prefix_length, 32);
        }
    }
    let result = bundle.lookup_ip("FD42:1234::1".parse().unwrap()).unwrap();
    assert_eq!(result.ip.to_string(), "fd42:1234::1");
    for found in result.records.values() {
        assert_eq!(found.network, "fd42:1234::1/128");
        assert_eq!(found.prefix_length, 128);
    }
}

#[test]
fn asns_are_ordered_by_asn() {
    let directory = fixture_copy();
    let path = directory.path().join("asn-index.json");
    let mut index = read_json(&path);
    let mut extra = index["asns"]["4242420001"].clone();
    extra["asn"] = json!(64512);
    index["asns"]["64512"] = extra;
    write_json(&path, &index);
    let bundle = Bundle::open(directory.path()).unwrap();
    let asns: Vec<u32> = bundle.asns().map(|info| info.asn).collect();
    assert_eq!(asns, [64512, 4_242_420_001]);
    let fixtures = Bundle::open(fixtures()).unwrap();
    assert_eq!(
        fixtures.asns().map(|info| info.asn).collect::<Vec<_>>(),
        [4_242_420_001]
    );
}

#[test]
fn release_metadata_exposes_typed_fields() {
    let directory = fixture_copy();
    let path = directory.path().join("metadata.json");
    let mut metadata = read_json(&path);
    metadata["release_tag"] = json!("v-test");
    metadata["route_observed_at"] =
        json!({"first": "2026-11-15T07:43:11Z", "last": "2026-11-15T10:59:05Z"});
    metadata["unlisted"] = json!({"kept": true});
    write_json(&path, &metadata);
    let bundle = Bundle::open(directory.path()).unwrap();
    let release = bundle.release_metadata();
    assert_eq!(release.release_tag.as_deref(), Some("v-test"));
    let window = release.route_observed_at.as_ref().unwrap();
    assert_eq!(window.last, "2026-11-15T10:59:05Z");
    assert_eq!(release.extra["unlisted"], json!({"kept": true}));
    assert!(release.release_repository.len() > 1);
    let plain = Bundle::open(fixtures()).unwrap();
    assert_eq!(plain.release_metadata().release_tag, None);
}

fn assert_invalid_bundle(directory: &Path, file: &str) {
    match failure(Bundle::open(directory)) {
        Error::InvalidBundle { file: actual, .. } => assert_eq!(actual, file),
        other => panic!("expected an invalid bundle error for {file}, got {other:?}"),
    }
}

#[test]
fn invalid_bundles_are_reported_with_the_offending_file() {
    let directory = fixture_copy();
    let path = directory.path().join("metadata.json");
    let mut metadata = read_json(&path);
    metadata["schema_version"] = json!("1");
    write_json(&path, &metadata);
    assert_invalid_bundle(directory.path(), "metadata.json");

    let directory = fixture_copy();
    write_json(
        &directory.path().join("metadata.json"),
        &json!({"schema_version": "2"}),
    );
    assert_invalid_bundle(directory.path(), "metadata.json");

    let directory = fixture_copy();
    let path = directory.path().join("metadata.json");
    let mut metadata = read_json(&path);
    metadata["database_types"] = json!({ASN_DB: "DN42-GeoIP2-Country"});
    write_json(&path, &metadata);
    assert_invalid_bundle(directory.path(), "metadata.json");

    let directory = fixture_copy();
    let path = directory.path().join("asn-index.json");
    let mut index = read_json(&path);
    let record = index["asns"]["4242420001"].take();
    index["asns"] = json!({"4242420002": record});
    write_json(&path, &index);
    assert_invalid_bundle(directory.path(), "asn-index.json");

    let directory = fixture_copy();
    write_json(
        &directory.path().join("asn-index.json"),
        &json!({"schema_version": "1", "asns": {}}),
    );
    assert_invalid_bundle(directory.path(), "asn-index.json");

    let directory = fixture_copy();
    fs::remove_file(directory.path().join("LICENSE-Unicode.txt")).unwrap();
    assert_invalid_bundle(directory.path(), "LICENSE-Unicode.txt");

    let directory = fixture_copy();
    fs::remove_file(directory.path().join("LICENSE-Unicode.txt")).unwrap();
    fs::create_dir(directory.path().join("LICENSE-Unicode.txt")).unwrap();
    assert_invalid_bundle(directory.path(), "LICENSE-Unicode.txt");

    let directory = fixture_copy();
    fs::copy(
        directory.path().join("DN42-IPDB-Country.mmdb"),
        directory.path().join(ASN_DB),
    )
    .unwrap();
    assert_invalid_bundle(directory.path(), ASN_DB);

    let directory = fixture_copy();
    fs::write(directory.path().join(CITY), b"not a database").unwrap();
    assert_invalid_bundle(directory.path(), CITY);
}

fn assert_invalid_after(file: &str, edit: impl FnOnce(&mut Value)) {
    let directory = fixture_copy();
    let path = directory.path().join(file);
    let mut document = read_json(&path);
    edit(&mut document);
    write_json(&path, &document);
    assert_invalid_bundle(directory.path(), file);
}

#[test]
fn null_optional_fields_are_invalid_and_absent_ones_are_not() {
    for field in [
        "release_tag",
        "release_url",
        "built_at",
        "registry_commit",
        "registry_committed_at",
        "route_observed_at",
        "database_types",
    ] {
        assert_invalid_after("metadata.json", |metadata| metadata[field] = Value::Null);
    }
    assert_invalid_after("asn-index.json", |index| {
        index["asns"]["4242420001"]["as_name"] = Value::Null;
    });
    assert_invalid_after("asn-index.json", |index| {
        index["asns"]["4242420001"]["observations"] = json!([{
            "target": "172.20.0.0/24", "asn": null, "kind": "ptr", "status": "ok",
            "method": "dns", "source": "test", "authority": "test",
            "observed_at": "2026-11-15T07:43:11Z"
        }]);
    });
    assert_invalid_after("asn-index.json", |index| {
        index["asns"]["4242420001"]["observations"] = json!([{
            "target": "172.20.0.0/24", "kind": "ptr", "value": null, "status": "ok",
            "method": "dns", "source": "test", "authority": "test",
            "observed_at": "2026-11-15T07:43:11Z"
        }]);
    });

    let directory = fixture_copy();
    let path = directory.path().join("asn-index.json");
    let mut index = read_json(&path);
    index["asns"]["4242420001"]["observations"] = json!([{
        "target": "172.20.0.0/24", "kind": "ptr", "status": "ok", "method": "dns",
        "source": "test", "authority": "test", "observed_at": "2026-11-15T07:43:11Z"
    }]);
    write_json(&path, &index);
    let bundle = Bundle::open(directory.path()).unwrap();
    let info = bundle.lookup_asn(4_242_420_001).unwrap();
    assert_eq!(
        (info.observations[0].asn, &info.observations[0].value),
        (None, &None)
    );

    let directory = fixture_copy();
    let path = directory.path().join("metadata.json");
    let mut metadata = read_json(&path);
    metadata.as_object_mut().unwrap().remove("database_types");
    metadata.as_object_mut().unwrap().remove("release_tag");
    write_json(&path, &metadata);
    let bundle = Bundle::open(directory.path()).unwrap();
    assert_eq!(bundle.release_metadata().release_tag, None);
    assert_eq!(bundle.release_metadata().database_types, None);
}

#[test]
fn a_missing_bundle_file_is_an_invalid_bundle_caused_by_not_found() {
    let directory = fixture_copy();
    fs::remove_file(directory.path().join(CITY)).unwrap();
    match failure(Bundle::open(directory.path())) {
        Error::InvalidBundle { file, source, .. } => {
            assert_eq!(file, CITY);
            assert_eq!(source.unwrap().kind(), io::ErrorKind::NotFound);
        }
        other => panic!("expected an invalid bundle error, got {other:?}"),
    }
}

#[test]
fn explicit_download_and_cached_open_reuse_verified_bundle() {
    let server = ReleaseServer::start();
    let root = tempfile::tempdir().unwrap();
    let cache = server.cache(root.path());
    let update = cache.refresh().unwrap();
    assert!(update.changed);
    assert!(!update.recovered_cache);
    assert_eq!(server.calls.load(Ordering::Relaxed), 8);
    assert_eq!(
        update.bundle.lookup_asn(4_242_420_001).unwrap().asn,
        4_242_420_001
    );
    assert_usable(&cache.open_cached().unwrap());
    assert_eq!(server.calls.load(Ordering::Relaxed), 8);
    let again = cache.refresh().unwrap();
    assert!(!again.changed);
    assert!(!again.recovered_cache);
    assert_usable(&again.bundle);
    assert_eq!(server.calls.load(Ordering::Relaxed), 9);
}

#[test]
fn download_creates_the_content_addressed_version() {
    let server = ReleaseServer::start();
    let root = tempfile::tempdir().unwrap();
    let update = server.cache(root.path()).refresh().unwrap();
    assert!(update.changed);
    assert_eq!(update.directory.file_name().unwrap(), FIXTURE_VERSION);
    assert_usable(&update.bundle);
    let pointer = read_json(&cache_directory(root.path()).join("current.json"));
    assert_eq!(pointer["version"], FIXTURE_VERSION);
    assert_eq!(pointer["checksums"].as_object().unwrap().len(), FILES.len());
    let mut names: Vec<_> = fs::read_dir(&update.directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    let mut expected = FILES.map(String::from).to_vec();
    expected.sort();
    assert_eq!(names, expected);
}

#[test]
fn download_heals_a_corrupted_version_and_a_corrupted_pointer() {
    let server = ReleaseServer::start();
    let root = tempfile::tempdir().unwrap();
    let cache = server.cache(root.path());
    cache.refresh().unwrap();
    let directory = cache_directory(root.path());

    fs::write(directory.join(FIXTURE_VERSION).join(CITY), b"damaged").unwrap();
    let healed = cache.refresh().unwrap();
    assert!(healed.changed && healed.recovered_cache);
    assert_usable(&cache.open_cached().unwrap());

    fs::remove_file(directory.join(FIXTURE_VERSION).join(ASN_DB)).unwrap();
    let healed = cache.refresh().unwrap();
    assert!(healed.changed && healed.recovered_cache);

    fs::write(directory.join("current.json"), b"{not json").unwrap();
    let healed = cache.refresh().unwrap();
    assert!(healed.changed && healed.recovered_cache);
    assert_usable(&cache.open_cached().unwrap());

    fs::write(
        directory.join("current.json"),
        b"{\"version\":\"short\",\"checksums\":{}}",
    )
    .unwrap();
    assert!(cache.refresh().unwrap().recovered_cache);

    let settled = cache.refresh().unwrap();
    assert!(!settled.changed && !settled.recovered_cache);
}

#[test]
fn open_cached_reports_a_missing_cache_and_a_damaged_version() {
    let server = ReleaseServer::start();
    let root = tempfile::tempdir().unwrap();
    let cache = server.cache(root.path());
    assert!(matches!(
        failure(cache.open_cached()),
        Error::CacheMissing(path) if path.ends_with("rust/v2/current.json")
    ));
    cache.refresh().unwrap();
    let city = cache_directory(root.path())
        .join(FIXTURE_VERSION)
        .join(CITY);
    fs::write(&city, b"damaged").unwrap();
    assert!(matches!(
        failure(cache.open_cached()),
        Error::ChecksumMismatch { file } if file == CITY
    ));
    fs::remove_file(&city).unwrap();
    match failure(cache.open_cached()) {
        Error::InvalidBundle { file, source, .. } => {
            assert_eq!(file, CITY);
            assert_eq!(source.unwrap().kind(), io::ErrorKind::NotFound);
        }
        other => panic!("expected an invalid bundle error, got {other:?}"),
    }
}

#[test]
fn concurrent_cached_opens_succeed() {
    let server = ReleaseServer::start();
    let root = tempfile::tempdir().unwrap();
    server.cache(root.path()).refresh().unwrap();
    thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| server.cache(root.path()).open_cached()))
            .collect();
        for handle in handles {
            assert_usable(&handle.join().unwrap().unwrap());
        }
    });
}

fn expect_failure(update: Result<Update>) -> Error {
    match update {
        Ok(_) => panic!("expected the refresh to fail"),
        Err(error) => error,
    }
}

/// Redirect targets that are refused: plain HTTP to another host, empty user info,
/// a fragment, an unparsable reference and an endless loop.
const REJECTED_REDIRECTS: [&str; 5] = [
    "http://192.0.2.1/blocked.mmdb",
    "https://@example.org/blocked.mmdb",
    "https://example.org/blocked.mmdb#fragment",
    "http://[::1",
    "/DN42-IPDB-City.mmdb",
];

#[test]
fn failed_and_cancelled_downloads_preserve_the_active_pointer() {
    let server = ReleaseServer::start();
    let root = tempfile::tempdir().unwrap();
    let cache = server.cache(root.path());
    let initial = cache.refresh().unwrap();
    let pointer_path = cache_directory(root.path()).join("current.json");
    let pointer = fs::read(&pointer_path).unwrap();
    for mode in 0..10usize {
        {
            let mut state = server.state.lock().unwrap();
            state.revision += 1;
            state.corrupt_city = mode == 0;
            state.wrong_asn_type = mode == 1;
            state.missing_file = (mode == 2).then(|| ASN_DB.to_string());
            state.oversize_manifest = mode == 4;
            state.redirect_city = mode
                .checked_sub(5)
                .map(|index| REJECTED_REDIRECTS[index].to_string());
            state.cancel_city = None;
        }
        let cancellation = Cancellation::default();
        if mode == 3 {
            server.state.lock().unwrap().cancel_city = Some(cancellation.clone());
        }
        let error = expect_failure(cache.refresh_with_cancel(&cancellation));
        match (mode, &error) {
            (0, Error::ChecksumMismatch { file }) => assert_eq!(file, CITY),
            (1, Error::InvalidBundle { file, .. }) => assert_eq!(file, ASN_DB),
            (2, Error::HttpStatus { url, status }) => {
                assert_eq!(*status, 404);
                assert!(url.ends_with(ASN_DB));
            }
            (3, Error::Cancelled) | (4, Error::SizeLimit(_)) | (5..=9, Error::InvalidUrl(_)) => {}
            _ => panic!("mode {mode}: unexpected error {error:?}"),
        }
        assert_eq!(fs::read(&pointer_path).unwrap(), pointer);
        assert_usable(&cache.open_cached().unwrap());
    }
    assert_usable(&initial.bundle);
    let cancellation = Cancellation::default();
    cancellation.cancel();
    assert!(matches!(
        expect_failure(cache.refresh_with_cancel(&cancellation)),
        Error::Cancelled
    ));
    assert_eq!(fs::read(&pointer_path).unwrap(), pointer);
}

#[test]
fn redirects_may_carry_a_query() {
    let server = ReleaseServer::start();
    server.state.lock().unwrap().redirect_signed = true;
    let root = tempfile::tempdir().unwrap();
    let update = server.cache(root.path()).refresh().unwrap();
    assert!(update.changed);
    assert_eq!(update.directory.file_name().unwrap(), FIXTURE_VERSION);
    assert_usable(&update.bundle);
}

#[test]
fn failed_activation_removes_its_new_version_directory() {
    let server = ReleaseServer::start();
    let root = tempfile::tempdir().unwrap();
    let cache = server.cache(root.path());
    let initial = cache.refresh().unwrap();
    let pointer = cache_directory(root.path()).join("current.json");
    {
        let mut state = server.state.lock().unwrap();
        state.revision = 1;
        state.block_pointer = Some(pointer.clone());
    }
    assert!(cache.refresh().is_err());
    assert!(pointer.is_dir());
    assert!(initial.directory.is_dir());
    assert_usable(&initial.bundle);
    let directories: Vec<_> = fs::read_dir(cache_directory(root.path()))
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
    let cache = server.cache(root.path());
    let initial = cache.refresh().unwrap();
    let custom = cache_directory(root.path()).join("a".repeat(64));
    fs::create_dir(&custom).unwrap();
    fs::write(custom.join("user.txt"), b"retain").unwrap();
    for revision in 1..4 {
        server.state.lock().unwrap().revision = revision;
        assert!(cache.refresh().unwrap().changed);
    }
    let owned = fs::read_dir(cache_directory(root.path()))
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
    assert_usable(&initial.bundle);
    assert_eq!(fs::read(custom.join("user.txt")).unwrap(), b"retain");
}

#[test]
fn download_removes_stale_stage_and_pointer_leftovers() {
    let server = ReleaseServer::start();
    let root = tempfile::tempdir().unwrap();
    let directory = cache_directory(root.path());
    fs::create_dir_all(directory.join(".stage-x")).unwrap();
    fs::write(directory.join(".stage-x/partial"), b"partial").unwrap();
    fs::write(directory.join(".current-x"), b"{}").unwrap();
    let update = server.cache(root.path()).refresh().unwrap();
    assert!(update.changed);
    assert!(!directory.join(".stage-x").exists());
    assert!(!directory.join(".current-x").exists());
    let mut leftovers: Vec<_> = fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with(".stage-") || name.starts_with(".current-"))
        .collect();
    leftovers.sort();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

fn hold_lock(directory: &Path, duration: Duration) -> thread::JoinHandle<()> {
    fs::create_dir_all(directory).unwrap();
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join(".update.lock"))
        .unwrap();
    file.lock().unwrap();
    thread::spawn(move || {
        thread::sleep(duration);
        drop(file);
    })
}

#[test]
fn a_held_writer_lock_is_awaited_until_the_deadline() {
    let server = ReleaseServer::start();
    let root = tempfile::tempdir().unwrap();
    let directory = cache_directory(root.path());
    let holder = hold_lock(&directory, Duration::from_millis(300));
    let started = Instant::now();
    let update = server.cache(root.path()).refresh().unwrap();
    assert!(update.changed);
    assert!(started.elapsed() >= Duration::from_millis(250));
    holder.join().unwrap();

    let holder = hold_lock(&directory, Duration::from_millis(600));
    let impatient = server
        .cache(root.path())
        .with_timeout(Duration::from_millis(100))
        .unwrap();
    let calls = server.calls.load(Ordering::Relaxed);
    assert!(matches!(
        expect_failure(impatient.refresh()),
        Error::LockTimeout
    ));
    assert_eq!(server.calls.load(Ordering::Relaxed), calls);
    holder.join().unwrap();
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
fn readers_ignore_the_writer_lock_held_by_another_process() {
    let server = ReleaseServer::start();
    let root = tempfile::tempdir().unwrap();
    server.cache(root.path()).refresh().unwrap();
    let cache = server
        .cache(root.path())
        .with_timeout(Duration::from_millis(100))
        .unwrap();
    let directory = cache_directory(root.path());
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
    assert_usable(&cache.open_cached().unwrap());
    assert!(matches!(
        expect_failure(cache.refresh()),
        Error::LockTimeout
    ));
    assert_eq!(server.calls.load(Ordering::Relaxed), calls);
}

#[test]
fn base_urls_are_validated() {
    let root = tempfile::tempdir().unwrap();
    for url in [
        "http://192.0.2.1/",
        "http://localhost/",
        "http://[2001:db8::1]/",
        "https://user:secret@example.com/",
        "https://:secret@example.com/",
        "https://example.com/?token=secret",
        "https://example.com/#fragment",
        "https://@example.com/",
        "https://:@example.com/",
        "https:@example.com/",
        "https:/@example.com/",
        " https://@example.com/",
        "https:\\\\@example.com/",
        "https://example.com/?",
        "https://example.com/#",
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:7f00:1]/",
        "ftp://example.com/",
        "not a url",
    ] {
        assert!(
            matches!(Cache::with_url(root.path(), url), Err(Error::InvalidUrl(_))),
            "{url}"
        );
    }
    for url in [
        "http://[::1]:8080/",
        "http://127.0.0.2/",
        "http://127.0.0.1:9/releases",
        "https://example.com/releases/",
        "https://example.com/at@path/",
    ] {
        assert!(Cache::with_url(root.path(), url).is_ok(), "{url}");
    }
}

#[test]
fn timeouts_have_no_upper_cap_and_must_be_positive() {
    let root = tempfile::tempdir().unwrap();
    let cache = || Cache::new(root.path()).unwrap();
    assert!(cache().with_timeout(Duration::from_secs(3600)).is_ok());
    assert!(matches!(
        cache().with_timeout(Duration::ZERO),
        Err(Error::InvalidArgument(_))
    ));
}

#[test]
fn timeouts_beyond_the_platform_clock_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let cache = Cache::new(root.path()).unwrap();
    assert!(matches!(
        cache.with_timeout(Duration::MAX),
        Err(Error::InvalidArgument(_))
    ));
}

#[test]
fn a_very_long_timeout_still_downloads() {
    let server = ReleaseServer::start();
    let root = tempfile::tempdir().unwrap();
    let cache = server
        .cache(root.path())
        .with_timeout(Duration::from_secs(365 * 24 * 3600))
        .unwrap();
    assert_usable(&cache.refresh().unwrap().bundle);
}

#[cfg(unix)]
#[test]
fn cache_entries_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let server = ReleaseServer::start();
    let root = tempfile::tempdir().unwrap();
    let update = server.cache(root.path()).refresh().unwrap();
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    let directory = cache_directory(root.path());
    assert_eq!(mode(&directory), 0o700);
    assert_eq!(mode(&update.directory), 0o700);
    for name in FILES {
        assert_eq!(mode(&update.directory.join(name)), 0o600, "{name}");
    }
    assert_eq!(mode(&directory.join("current.json")), 0o600);
    assert_eq!(mode(&directory.join(".update.lock")), 0o600);
}

#[test]
fn files_listing_matches_the_fixture_bundle() {
    let mut fixtures: Vec<_> = fs::read_dir(fixtures())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    fixtures.sort();
    let mut files = FILES.map(String::from).to_vec();
    files.sort();
    assert_eq!(fixtures, files);
    assert_eq!(
        "172.20.0.1".parse::<IpAddr>().unwrap().to_string(),
        "172.20.0.1"
    );
}
