//! Read BIRDCC DN42 IPDB release bundles and update a verified local cache.

use std::collections::BTreeMap;
use std::fmt::Display;
use std::fs::{self, DirBuilder, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use maxminddb::Reader;
use reqwest::{
    Url,
    blocking::{Client, Response},
    header::LOCATION,
    redirect::Policy,
};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tempfile::Builder;
use thiserror::Error;

pub const DEFAULT_RELEASE_URL: &str =
    "https://github.com/bird-chinese-community/DN42-IPDB-Releases/releases/latest/download/";
/// Size limit of each MMDB file and of asn-index.json.
pub const MAX_DATABASE_BYTES: usize = 32 * 1024 * 1024;
/// Size limit of metadata.json and LICENSE-Unicode.txt.
pub const MAX_TEXT_BYTES: usize = 1024 * 1024;
/// Size limit of checksums.json and current.json.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const LOCK_POLL: Duration = Duration::from_millis(20);
const MAX_REDIRECTS: usize = 10;
const OPEN_ATTEMPTS: usize = 3;
const POINTER_FILE: &str = "current.json";
const MANIFEST_FILE: &str = "checksums.json";
const LOCK_FILE: &str = ".update.lock";
const STAGE_PREFIX: &str = ".stage-";
const PENDING_PREFIX: &str = ".current-";
const ASN_INDEX_FILE: &str = "asn-index.json";
const METADATA_FILE: &str = "metadata.json";
const LICENSE_FILE: &str = "LICENSE-Unicode.txt";

struct DatabaseSpec {
    key: &'static str,
    file: &'static str,
    database_type: &'static str,
}

const DATABASES: [DatabaseSpec; 4] = [
    DatabaseSpec {
        key: "country",
        file: "DN42-IPDB-Country.mmdb",
        database_type: "DN42-GeoIP2-Country",
    },
    DatabaseSpec {
        key: "city",
        file: "DN42-IPDB-City.mmdb",
        database_type: "DN42-GeoIP2-City",
    },
    DatabaseSpec {
        key: "asn",
        file: "DN42-IPDB-ASN.mmdb",
        database_type: "DN42-GeoLite2-ASN",
    },
    DatabaseSpec {
        key: "connection_type",
        file: "DN42-IPDB-Connection-Type.mmdb",
        database_type: "DN42-GeoIP2-Connection-Type",
    },
];
const SIDECARS: [&str; 3] = [ASN_INDEX_FILE, METADATA_FILE, LICENSE_FILE];
/// Number of files in a release bundle.
pub const FILE_COUNT: usize = DATABASES.len() + SIDECARS.len();
/// The files of a release bundle: the four databases followed by the sidecars.
pub const FILES: [&str; FILE_COUNT] = required_files();

const fn required_files() -> [&'static str; FILE_COUNT] {
    let mut files = [""; FILE_COUNT];
    let mut index = 0;
    while index < DATABASES.len() {
        files[index] = DATABASES[index].file;
        index += 1;
    }
    let mut sidecar = 0;
    while sidecar < SIDECARS.len() {
        files[index] = SIDECARS[sidecar];
        index += 1;
        sidecar += 1;
    }
    files
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
    #[error("release request to {url} failed: {source}")]
    Http {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("{file}: MaxMind lookup failed: {source}")]
    Maxmind {
        file: String,
        #[source]
        source: maxminddb::MaxMindDbError,
    },
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("invalid release URL: {0}")]
    InvalidUrl(String),
    #[error("invalid DN42 bundle: {file}: {reason}")]
    InvalidBundle {
        file: String,
        reason: String,
        /// The I/O error behind a missing file.
        #[source]
        source: Option<io::Error>,
    },
    #[error("checksum mismatch: {file}")]
    ChecksumMismatch { file: String },
    #[error("size limit exceeded: {0}")]
    SizeLimit(String),
    #[error("{url}: unexpected HTTP status {status}")]
    HttpStatus { url: String, status: u16 },
    #[error("timed out waiting for the cache update lock")]
    LockTimeout,
    #[error("no cached DN42 bundle: {}", .0.display())]
    CacheMissing(PathBuf),
    #[error("DN42 update was cancelled")]
    Cancelled,
    #[error("DN42 update deadline expired")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Deserializes an optional field that may be absent but not null.
fn present<'de, T, D>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    T::deserialize(deserializer).map(Some)
}

impl Error {
    fn io(context: impl Display) -> impl Fn(io::Error) -> Self {
        let context = context.to_string();
        move |source| Self::Io {
            context: context.clone(),
            source,
        }
    }

    fn invalid(file: &str, reason: impl Display) -> Self {
        Self::InvalidBundle {
            file: file.to_string(),
            reason: reason.to_string(),
            source: None,
        }
    }

    /// A file is missing: a plain I/O error or an invalid bundle caused by one.
    fn is_not_found(&self) -> bool {
        match self {
            Self::Io { source, .. } => source.kind() == io::ErrorKind::NotFound,
            Self::InvalidBundle {
                source: Some(source),
                ..
            } => source.kind() == io::ErrorKind::NotFound,
            _ => false,
        }
    }

    /// A file of the version directory is missing or differs from the pointer.
    fn is_missing_or_changed(&self) -> bool {
        self.is_not_found() || matches!(self, Self::ChecksumMismatch { .. })
    }

    /// The cached version directory cannot be used and must be downloaded again.
    fn is_damaged(&self) -> bool {
        self.is_missing_or_changed()
            || matches!(self, Self::SizeLimit(_) | Self::InvalidBundle { .. })
    }

    /// The pointer file exists but its content cannot be used.
    fn is_invalid_pointer(&self) -> bool {
        matches!(self, Self::SizeLimit(_) | Self::InvalidBundle { .. })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Observation {
    pub target: String,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub asn: Option<u32>,
    pub kind: String,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub value: Option<String>,
    pub status: String,
    pub method: String,
    pub source: String,
    pub authority: String,
    pub observed_at: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegisteredCountry {
    pub iso_code: String,
    pub names: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AsnInfo {
    pub asn: u32,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub as_name: Option<String>,
    pub registered_countries: Vec<RegisteredCountry>,
    pub prefixes: Vec<String>,
    pub observed_network_types: Vec<String>,
    pub observations: Vec<Observation>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Observation times of the oldest and newest route in a release.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouteWindow {
    pub first: String,
    pub last: String,
}

/// The release metadata document; keys outside the known fields are kept in `extra`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReleaseMetadata {
    pub schema_version: String,
    pub release_repository: String,
    pub copyright: String,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub release_tag: Option<String>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub release_url: Option<String>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub built_at: Option<String>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub registry_commit: Option<String>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub registry_committed_at: Option<String>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub route_observed_at: Option<RouteWindow>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub database_types: Option<BTreeMap<String, String>>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// A database hit: the canonical CIDR of the matched network in the address family
/// of the looked-up IP, its prefix length, and the decoded record.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Match {
    pub network: String,
    pub prefix_length: u8,
    pub data: Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IpLookup {
    pub ip: IpAddr,
    pub records: BTreeMap<String, Match>,
}

#[derive(Deserialize)]
struct AsnIndex {
    schema_version: String,
    asns: BTreeMap<String, AsnInfo>,
}

struct Database {
    file: &'static str,
    reader: Reader<Vec<u8>>,
}

impl Database {
    fn lookup(&self, ip: IpAddr) -> Result<Option<Match>> {
        let fail = |source| Error::Maxmind {
            file: self.file.to_string(),
            source,
        };
        let result = self.reader.lookup(ip).map_err(fail)?;
        let Some(data) = result.decode::<Value>().map_err(fail)? else {
            return Ok(None);
        };
        if !data.as_object().is_some_and(|object| !object.is_empty()) {
            return Ok(None);
        }
        let network = result.network().map_err(fail)?;
        Ok(Some(Match {
            network: format!("{}/{}", network.network(), network.prefix()),
            prefix_length: network.prefix(),
            data,
        }))
    }
}

type Files = BTreeMap<&'static str, Vec<u8>>;
type Checksums = BTreeMap<String, String>;

/// All four readers and the ASN index are owned in memory; lookups perform no I/O.
pub struct Bundle {
    databases: BTreeMap<&'static str, Database>,
    asns: BTreeMap<u32, AsnInfo>,
    release: ReleaseMetadata,
}

impl Bundle {
    pub fn open(directory: impl AsRef<Path>) -> Result<Self> {
        Self::from_files(read_files(directory.as_ref(), missing_as_invalid)?)
    }

    fn from_files(mut files: Files) -> Result<Self> {
        let release = parse_metadata(&take_file(&mut files, METADATA_FILE))?;
        let asns = parse_asn_index(&take_file(&mut files, ASN_INDEX_FILE))?;
        take_file(&mut files, LICENSE_FILE);
        let mut databases = BTreeMap::new();
        for spec in &DATABASES {
            let reader = open_database(spec, take_file(&mut files, spec.file), &release)?;
            databases.insert(
                spec.key,
                Database {
                    file: spec.file,
                    reader,
                },
            );
        }
        Ok(Self {
            databases,
            asns,
            release,
        })
    }

    /// IPv4-mapped IPv6 addresses are looked up and reported as IPv4.
    pub fn lookup_ip(&self, ip: IpAddr) -> Result<IpLookup> {
        let ip = match ip {
            IpAddr::V6(address) => address.to_ipv4_mapped().map_or(ip, IpAddr::V4),
            IpAddr::V4(_) => ip,
        };
        let mut records = BTreeMap::new();
        for (key, database) in &self.databases {
            if let Some(found) = database.lookup(ip)? {
                records.insert((*key).to_string(), found);
            }
        }
        Ok(IpLookup { ip, records })
    }

    pub fn lookup_asn(&self, asn: u32) -> Option<&AsnInfo> {
        self.asns.get(&asn)
    }

    /// Every ASN record ordered by ASN ascending.
    pub fn asns(&self) -> impl Iterator<Item = &AsnInfo> {
        self.asns.values()
    }

    pub fn release_metadata(&self) -> &ReleaseMetadata {
        &self.release
    }

    pub fn database_metadata(&self) -> BTreeMap<&str, &maxminddb::Metadata> {
        self.databases
            .iter()
            .map(|(key, database)| (*key, database.reader.metadata()))
            .collect()
    }
}

fn take_file(files: &mut Files, name: &str) -> Vec<u8> {
    files
        .remove(name)
        .unwrap_or_else(|| unreachable!("{name} is read with the bundle files"))
}

fn parse_json<T: DeserializeOwned>(file: &str, bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|error| Error::invalid(file, error))
}

fn require_schema_version(file: &str, version: &str) -> Result<()> {
    if version != "2" {
        return Err(Error::invalid(
            file,
            format!("schema_version must be \"2\", got {version:?}"),
        ));
    }
    Ok(())
}

fn parse_metadata(bytes: &[u8]) -> Result<ReleaseMetadata> {
    let metadata: ReleaseMetadata = parse_json(METADATA_FILE, bytes)?;
    require_schema_version(METADATA_FILE, &metadata.schema_version)?;
    for (name, value) in [
        ("release_repository", &metadata.release_repository),
        ("copyright", &metadata.copyright),
    ] {
        if value.is_empty() {
            return Err(Error::invalid(METADATA_FILE, format!("{name} is empty")));
        }
    }
    Ok(metadata)
}

fn parse_asn_index(bytes: &[u8]) -> Result<BTreeMap<u32, AsnInfo>> {
    let index: AsnIndex = parse_json(ASN_INDEX_FILE, bytes)?;
    require_schema_version(ASN_INDEX_FILE, &index.schema_version)?;
    index
        .asns
        .into_iter()
        .map(|(key, info)| {
            if key != info.asn.to_string() {
                return Err(Error::invalid(
                    ASN_INDEX_FILE,
                    format!("key {key:?} does not match asn {}", info.asn),
                ));
            }
            Ok((info.asn, info))
        })
        .collect()
}

fn open_database(
    spec: &DatabaseSpec,
    bytes: Vec<u8>,
    release: &ReleaseMetadata,
) -> Result<Reader<Vec<u8>>> {
    let reader = Reader::from_source(bytes).map_err(|error| Error::invalid(spec.file, error))?;
    let actual = reader.metadata().database_type.as_str();
    if actual != spec.database_type {
        return Err(Error::invalid(
            spec.file,
            format!(
                "expected database type {}, got {actual}",
                spec.database_type
            ),
        ));
    }
    if let Some(declared) = release
        .database_types
        .as_ref()
        .and_then(|types| types.get(spec.file))
        && declared != actual
    {
        return Err(Error::invalid(
            METADATA_FILE,
            format!(
                "database_types declares {declared} for {}, file is {actual}",
                spec.file
            ),
        ));
    }
    Ok(reader)
}

/// A cloneable cancellation flag checked between blocking requests and body reads.
#[derive(Clone, Default)]
pub struct Cancellation(Arc<AtomicBool>);

impl Cancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    fn check(&self, deadline: Instant) -> Result<()> {
        if self.0.load(Ordering::Acquire) {
            return Err(Error::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(Error::Timeout);
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct Pointer {
    version: String,
    checksums: Checksums,
}

#[derive(Deserialize)]
struct RawPointer {
    version: String,
    checksums: Map<String, Value>,
}

pub struct Update {
    pub directory: PathBuf,
    pub changed: bool,
    /// The previous pointer or version directory was unusable and was replaced.
    pub recovered_cache: bool,
    pub bundle: Bundle,
}

/// Explicit updates use cache_root/rust/v2 and retain the current and previous bundle.
pub struct Cache {
    directory: PathBuf,
    base_url: Url,
    timeout: Duration,
}

impl Cache {
    pub fn new(cache_root: impl AsRef<Path>) -> Result<Self> {
        Self::with_url(cache_root, DEFAULT_RELEASE_URL)
    }

    pub fn with_url(cache_root: impl AsRef<Path>, base_url: &str) -> Result<Self> {
        if cache_root.as_ref().as_os_str().is_empty() {
            return Err(Error::InvalidArgument("cache directory is required".into()));
        }
        let mut url = Url::parse(base_url)
            .map_err(|error| Error::InvalidUrl(format!("{base_url}: {error}")))?;
        check_base_url(base_url, &url).map_err(Error::InvalidUrl)?;
        if !url.path().ends_with('/') {
            url.set_path(&format!("{}/", url.path()));
        }
        Ok(Self {
            directory: cache_root.as_ref().join("rust").join("v2"),
            base_url: url,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Sets the deadline covering the writer-lock wait and all requests.
    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() {
            return Err(Error::InvalidArgument(
                "timeout must be greater than zero".into(),
            ));
        }
        deadline_after(timeout)?;
        self.timeout = timeout;
        Ok(self)
    }

    /// Opens the current cached bundle without taking the writer lock.
    pub fn open_cached(&self) -> Result<Bundle> {
        open_with_retry(&self.directory, |pointer| {
            verified_read(&self.directory.join(&pointer.version), &pointer.checksums)
        })
    }

    pub fn refresh(&self) -> Result<Update> {
        self.refresh_with_cancel(&Cancellation::default())
    }

    pub fn refresh_with_cancel(&self, cancellation: &Cancellation) -> Result<Update> {
        let deadline = deadline_after(self.timeout)?;
        let _lock = lock_cache(&self.directory, deadline, cancellation)?;
        let session = Session::new(&self.base_url, deadline, cancellation)?;
        let checksums = session.fetch_checksums()?;
        let (previous, mut recovered_cache) = read_previous(&self.directory)?;
        if let Some(previous) = previous.as_ref().filter(|p| p.checksums == checksums) {
            let directory = self.directory.join(&previous.version);
            match verified_read(&directory, &checksums) {
                Ok(bundle) => {
                    cancellation.check(deadline)?;
                    return Ok(Update {
                        directory,
                        changed: false,
                        recovered_cache: false,
                        bundle,
                    });
                }
                Err(error) if error.is_damaged() => recovered_cache = true,
                Err(error) => return Err(error),
            }
        }
        self.install(&session, checksums, previous.as_ref(), recovered_cache)
    }

    fn install(
        &self,
        session: &Session,
        checksums: Checksums,
        previous: Option<&Pointer>,
        recovered_cache: bool,
    ) -> Result<Update> {
        let stage = create_stage(&self.directory)?;
        let bundle = session.download_bundle(stage.path(), &checksums)?;
        let version = content_version(&checksums);
        let directory = self.directory.join(&version);
        session.check()?;
        let mut created = CreatedVersion(None);
        if place_version(stage.path(), &directory, &checksums)? {
            created.0 = Some(directory.clone());
        }
        let retained = [Some(version.as_str()), previous.map(|p| p.version.as_str())];
        prune(&self.directory, &retained, stage.path())?;
        commit_pointer(&self.directory, &Pointer { version, checksums }, session)?;
        created.0 = None;
        Ok(Update {
            directory,
            changed: true,
            recovered_cache,
            bundle,
        })
    }
}

/// The deadline of an operation starting now; rejects durations the platform clock cannot hold.
fn deadline_after(timeout: Duration) -> Result<Instant> {
    Instant::now().checked_add(timeout).ok_or_else(|| {
        Error::InvalidArgument(format!(
            "timeout {timeout:?} exceeds the platform clock range"
        ))
    })
}

fn create_stage(cache: &Path) -> Result<tempfile::TempDir> {
    let mut builder = Builder::new();
    builder.prefix(STAGE_PREFIX);
    #[cfg(unix)]
    builder.permissions(<fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700));
    builder
        .tempdir_in(cache)
        .map_err(Error::io(cache.display()))
}

/// Removes a version directory created by this run unless the pointer was switched.
struct CreatedVersion(Option<PathBuf>);

impl Drop for CreatedVersion {
    fn drop(&mut self) {
        if let Some(directory) = &self.0 {
            let _ = fs::remove_dir_all(directory);
        }
    }
}

fn file_limit(name: &str) -> usize {
    match name {
        POINTER_FILE | MANIFEST_FILE => MAX_MANIFEST_BYTES,
        METADATA_FILE | LICENSE_FILE => MAX_TEXT_BYTES,
        _ => MAX_DATABASE_BYTES,
    }
}

/// Reads one regular file, enforcing the size limit while reading.
fn read_file(directory: &Path, name: &str) -> Result<Vec<u8>> {
    let path = directory.join(name);
    let context = path.display().to_string();
    let io_error = Error::io(&context);
    if !fs::metadata(&path).map_err(&io_error)?.is_file() {
        return Err(Error::invalid(name, "not a regular file"));
    }
    let file = File::open(&path).map_err(&io_error)?;
    let limit = file_limit(name);
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(&io_error)?;
    if bytes.len() > limit {
        return Err(Error::SizeLimit(name.to_string()));
    }
    Ok(bytes)
}

fn read_files(directory: &Path, on_error: impl Fn(&str, Error) -> Error) -> Result<Files> {
    FILES
        .iter()
        .map(|name| {
            read_file(directory, name)
                .map(|bytes| (*name, bytes))
                .map_err(|error| on_error(name, error))
        })
        .collect()
}

/// A bundle directory with a missing file is an invalid bundle naming that file.
fn missing_as_invalid(name: &str, error: Error) -> Error {
    match error {
        Error::Io { source, .. } if source.kind() == io::ErrorKind::NotFound => {
            Error::InvalidBundle {
                file: name.to_string(),
                reason: "file is missing".into(),
                source: Some(source),
            }
        }
        error => error,
    }
}

fn checksum(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn verify_checksums(files: &Files, checksums: &Checksums) -> Result<()> {
    for (name, bytes) in files {
        if checksums.get(*name) != Some(&checksum(bytes)) {
            return Err(Error::ChecksumMismatch {
                file: (*name).to_string(),
            });
        }
    }
    Ok(())
}

/// Reads the seven files of a version directory once, verifies them and builds the bundle.
fn verified_read(directory: &Path, checksums: &Checksums) -> Result<Bundle> {
    let files = read_files(directory, missing_as_invalid)?;
    verify_checksums(&files, checksums)?;
    Bundle::from_files(files)
}

/// Extracts the digests of the required files; other keys are ignored.
fn required_checksums(file: &str, document: &Map<String, Value>) -> Result<Checksums> {
    FILES
        .iter()
        .map(|name| match document.get(*name).and_then(Value::as_str) {
            Some(digest) if is_digest(digest) => Ok(((*name).to_string(), digest.to_string())),
            _ => Err(Error::invalid(
                file,
                format!("missing or invalid checksum for {name}"),
            )),
        })
        .collect()
}

fn read_pointer(directory: &Path) -> Result<Pointer> {
    let bytes = match read_file(directory, POINTER_FILE) {
        Err(error) if error.is_not_found() => {
            return Err(Error::CacheMissing(directory.join(POINTER_FILE)));
        }
        result => result?,
    };
    let raw: RawPointer = parse_json(POINTER_FILE, &bytes)?;
    if !is_digest(&raw.version) {
        return Err(Error::invalid(
            POINTER_FILE,
            "version is not a 64-digit hex name",
        ));
    }
    Ok(Pointer {
        version: raw.version,
        checksums: required_checksums(POINTER_FILE, &raw.checksums)?,
    })
}

/// Returns the previous pointer and whether an unusable pointer was discarded.
fn read_previous(directory: &Path) -> Result<(Option<Pointer>, bool)> {
    match read_pointer(directory) {
        Ok(pointer) => Ok((Some(pointer), false)),
        Err(Error::CacheMissing(_)) => Ok((None, false)),
        Err(error) if error.is_invalid_pointer() => Ok((None, true)),
        Err(error) => Err(error),
    }
}

/// Opens the pointed version; when files vanished or changed because the pointer
/// moved, the pointer is read again and the open is retried.
fn open_with_retry(
    directory: &Path,
    mut open: impl FnMut(&Pointer) -> Result<Bundle>,
) -> Result<Bundle> {
    let mut pointer = read_pointer(directory)?;
    let mut attempt = 1;
    loop {
        let error = match open(&pointer) {
            Ok(bundle) => return Ok(bundle),
            Err(error) => error,
        };
        if attempt == OPEN_ATTEMPTS || !error.is_missing_or_changed() {
            return Err(error);
        }
        let latest = read_pointer(directory)?;
        if latest.version == pointer.version {
            return Err(error);
        }
        pointer = latest;
        attempt += 1;
    }
}

/// The version name is the SHA-256 of the compact JSON object of the required checksums.
fn content_version(checksums: &Checksums) -> String {
    let canonical = serde_json::to_vec(checksums).expect("string maps serialize to JSON");
    checksum(&canonical)
}

/// Moves the stage into place; returns false when an intact version already exists.
fn place_version(stage: &Path, directory: &Path, checksums: &Checksums) -> Result<bool> {
    let context = directory.display().to_string();
    if directory.exists() {
        match verified_read(directory, checksums) {
            Ok(_) => return Ok(false),
            Err(error) if error.is_damaged() => {
                fs::remove_dir_all(directory).map_err(Error::io(&context))?;
            }
            Err(error) => return Err(error),
        }
    }
    fs::rename(stage, directory).map_err(Error::io(&context))?;
    Ok(true)
}

fn commit_pointer(directory: &Path, pointer: &Pointer, session: &Session) -> Result<()> {
    let target = directory.join(POINTER_FILE);
    let context = target.display().to_string();
    let io_error = Error::io(&context);
    let bytes = serde_json::to_vec(pointer).expect("pointer serializes to JSON");
    let mut pending = Builder::new()
        .prefix(PENDING_PREFIX)
        .tempfile_in(directory)
        .map_err(&io_error)?;
    pending.write_all(&bytes).map_err(&io_error)?;
    pending.as_file().sync_all().map_err(&io_error)?;
    session.check()?;
    pending
        .persist(&target)
        .map_err(|error| io_error(error.error))?;
    Ok(())
}

/// Removes leftovers of earlier runs and unreferenced bundle directories made of
/// exactly the known files. Unknown directories are left alone.
fn prune(cache: &Path, retained: &[Option<&str>], stage: &Path) -> Result<()> {
    let context = cache.display().to_string();
    let io_error = Error::io(&context);
    for entry in fs::read_dir(cache).map_err(&io_error)? {
        let entry = entry.map_err(&io_error)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_dir = entry.file_type().map_err(&io_error)?.is_dir();
        let leftover = name.starts_with(STAGE_PREFIX) || name.starts_with(PENDING_PREFIX);
        if leftover && entry.path() != stage {
            remove_entry(&entry.path(), is_dir)?;
        } else if is_dir
            && is_digest(&name)
            && !retained.contains(&Some(name.as_str()))
            && holds_only_bundle_files(&entry.path())?
        {
            remove_entry(&entry.path(), true)?;
        }
    }
    Ok(())
}

fn remove_entry(path: &Path, is_dir: bool) -> Result<()> {
    let result = if is_dir {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    result.map_err(Error::io(&path.display().to_string()))
}

fn holds_only_bundle_files(directory: &Path) -> Result<bool> {
    let io_error = Error::io(directory.display());
    let entries = fs::read_dir(directory)
        .map_err(&io_error)?
        .collect::<io::Result<Vec<_>>>()
        .map_err(&io_error)?;
    Ok(entries.len() == FILES.len()
        && entries.iter().all(|entry| {
            entry.file_type().is_ok_and(|kind| kind.is_file())
                && FILES.iter().any(|file| entry.file_name() == *file)
        }))
}

fn has_credentials(url: &Url) -> bool {
    !url.username().is_empty() || url.password().is_some()
}

fn is_scheme(text: &str) -> bool {
    text.starts_with(|first: char| first.is_ascii_alphabetic())
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// The authority of an absolute or scheme-relative reference, taken from its raw text
/// because URL parsing drops an empty user info such as `https://@host/`. Special
/// schemes such as https take the authority after any number of slashes or
/// backslashes (`https:@host/` and `https:/@host/` name `host`).
fn raw_authority(raw: &str) -> Option<String> {
    let raw: String = raw
        .chars()
        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
        .collect();
    let raw = raw.trim_matches(|c: char| c <= ' ');
    let (has_scheme, rest) = match raw.split_once(':') {
        Some((scheme, rest)) if is_scheme(scheme) => (true, rest),
        _ => (false, raw),
    };
    let authority = rest.trim_start_matches(['/', '\\']);
    let slashes = rest.len() - authority.len();
    (has_scheme || slashes >= 2).then(|| {
        authority
            .split(['/', '\\', '?', '#'])
            .next()
            .unwrap_or_default()
            .to_string()
    })
}

fn raw_has_user_info(raw: &str) -> bool {
    raw_authority(raw).is_some_and(|authority| authority.contains('@'))
}

/// Loopback is 127.0.0.0/8 or ::1; IPv4-mapped IPv6 addresses do not count.
fn is_loopback_host(url: &Url) -> bool {
    let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']);
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => address.is_loopback(),
        Ok(IpAddr::V6(address)) => address == Ipv6Addr::LOCALHOST,
        Err(_) => false,
    }
}

/// A base URL has no credentials, query or fragment, even empty ones in its raw text;
/// HTTP is limited to loopback IP literals.
fn check_base_url(raw: &str, url: &Url) -> std::result::Result<(), String> {
    if url.host_str().is_none()
        || has_credentials(url)
        || raw_has_user_info(raw)
        || raw.contains(['?', '#'])
    {
        return Err(format!(
            "{url}: a host is required and credentials, query and fragment are not allowed"
        ));
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_host(url) => Ok(()),
        _ => Err(format!(
            "{url}: requires HTTPS or HTTP to a loopback IP literal"
        )),
    }
}

/// A redirect target has no credentials or fragment and uses HTTPS, or HTTP on the
/// loopback base origin. A query is allowed because release assets use signed URLs.
fn check_redirect(raw: &str, url: &Url, base: &Url) -> std::result::Result<(), String> {
    if has_credentials(url) || raw_has_user_info(raw) {
        return Err(format!("redirect to {url} carries credentials"));
    }
    if url.fragment().is_some() || raw.contains('#') {
        return Err(format!("redirect to {url} carries a fragment"));
    }
    let same_origin = base.scheme() == "http"
        && base.host_str() == url.host_str()
        && base.port_or_known_default() == url.port_or_known_default();
    match url.scheme() {
        "https" => Ok(()),
        "http" if same_origin => Ok(()),
        _ => Err(format!(
            "redirect to {url} requires HTTPS or the loopback base origin"
        )),
    }
}

fn request_error(url: &str, error: reqwest::Error) -> Error {
    if error.is_timeout() {
        return Error::Timeout;
    }
    Error::Http {
        url: url.to_string(),
        source: error,
    }
}

/// One refresh run: HTTP client, base URL, deadline and cancellation.
struct Session<'a> {
    client: Client,
    base_url: &'a Url,
    deadline: Instant,
    cancellation: &'a Cancellation,
}

impl<'a> Session<'a> {
    fn new(base_url: &'a Url, deadline: Instant, cancellation: &'a Cancellation) -> Result<Self> {
        let client = Client::builder()
            .redirect(Policy::none())
            .build()
            .map_err(|source| Error::Http {
                url: base_url.to_string(),
                source,
            })?;
        Ok(Self {
            client,
            base_url,
            deadline,
            cancellation,
        })
    }

    fn check(&self) -> Result<()> {
        self.cancellation.check(self.deadline)
    }

    /// Sends a GET request and follows at most ten redirects, validating each raw Location.
    fn send(&self, first: Url) -> Result<Response> {
        let mut url = first;
        for _ in 0..=MAX_REDIRECTS {
            self.check()?;
            let response = self
                .client
                .get(url.clone())
                .timeout(self.deadline.saturating_duration_since(Instant::now()))
                .send()
                .map_err(|error| request_error(url.as_str(), error))?;
            if !matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                return Ok(response);
            }
            url = self.redirect_target(&url, &response)?;
        }
        Err(Error::InvalidUrl(format!("{url}: too many redirects")))
    }

    fn redirect_target(&self, from: &Url, response: &Response) -> Result<Url> {
        let invalid = |reason: String| Error::InvalidUrl(format!("{from}: {reason}"));
        let raw = response
            .headers()
            .get(LOCATION)
            .ok_or_else(|| invalid("redirect without a Location header".into()))?
            .to_str()
            .map_err(|error| invalid(format!("unreadable Location header: {error}")))?;
        let target = from
            .join(raw)
            .map_err(|error| invalid(format!("unparsable Location {raw:?}: {error}")))?;
        check_redirect(raw, &target, self.base_url).map_err(Error::InvalidUrl)?;
        Ok(target)
    }

    fn fetch(&self, name: &str) -> Result<Vec<u8>> {
        let url = self
            .base_url
            .join(name)
            .map_err(|error| Error::InvalidUrl(format!("{name}: {error}")))?;
        let label = url.to_string();
        let limit = file_limit(name);
        let mut response = self.send(url)?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(Error::HttpStatus { url: label, status });
        }
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            return Err(Error::SizeLimit(label));
        }
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            self.check()?;
            let count = response.read(&mut chunk).map_err(|error| {
                if error.kind() == io::ErrorKind::TimedOut {
                    Error::Timeout
                } else {
                    Error::io(&label)(error)
                }
            })?;
            if count == 0 {
                return Ok(bytes);
            }
            if bytes.len() + count > limit {
                return Err(Error::SizeLimit(label));
            }
            bytes.extend_from_slice(&chunk[..count]);
        }
    }

    fn fetch_checksums(&self) -> Result<Checksums> {
        let document: Map<String, Value> = parse_json(MANIFEST_FILE, &self.fetch(MANIFEST_FILE)?)?;
        required_checksums(MANIFEST_FILE, &document)
    }

    /// Downloads, verifies and stores the seven files, then builds the bundle from those bytes.
    fn download_bundle(&self, stage: &Path, checksums: &Checksums) -> Result<Bundle> {
        let mut files = Files::new();
        for name in FILES {
            let bytes = self.fetch(name)?;
            if checksums.get(name) != Some(&checksum(&bytes)) {
                return Err(Error::ChecksumMismatch {
                    file: name.to_string(),
                });
            }
            write_private_file(&stage.join(name), &bytes)?;
            files.insert(name, bytes);
        }
        Bundle::from_files(files)
    }
}

fn private_file_options() -> OpenOptions {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let io_error = Error::io(path.display());
    let mut file = private_file_options()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(&io_error)?;
    file.write_all(bytes).map_err(&io_error)?;
    file.sync_all().map_err(&io_error)
}

fn create_private_dir_all(directory: &Path) -> Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(directory)
        .map_err(Error::io(&directory.display().to_string()))
}

/// Takes the exclusive writer lock, polling until acquired, the deadline or cancellation.
fn lock_cache(directory: &Path, deadline: Instant, cancellation: &Cancellation) -> Result<File> {
    create_private_dir_all(directory)?;
    let path = directory.join(LOCK_FILE);
    let io_error = Error::io(path.display());
    let file = private_file_options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(&io_error)?;
    loop {
        match cancellation.check(deadline) {
            Err(Error::Timeout) => return Err(Error::LockTimeout),
            result => result?,
        }
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) => {
                thread::sleep(LOCK_POLL.min(deadline.saturating_duration_since(Instant::now())));
            }
            Err(TryLockError::Error(error)) => return Err(io_error(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data")
    }

    fn fixture_checksums() -> Checksums {
        FILES
            .iter()
            .map(|name| {
                let bytes = fs::read(fixtures().join(name)).unwrap();
                ((*name).to_string(), checksum(&bytes))
            })
            .collect()
    }

    fn install_fixture_version(cache: &Path, version: &str) {
        let directory = cache.join(version);
        fs::create_dir(&directory).unwrap();
        for name in FILES {
            fs::copy(fixtures().join(name), directory.join(name)).unwrap();
        }
    }

    fn write_pointer(cache: &Path, version: &str, checksums: &Checksums) {
        let pointer = Pointer {
            version: version.to_string(),
            checksums: checksums.clone(),
        };
        fs::write(
            cache.join(POINTER_FILE),
            serde_json::to_vec(&pointer).unwrap(),
        )
        .unwrap();
    }

    fn open_pointed(cache: &Path, pointer: &Pointer) -> Result<Bundle> {
        verified_read(&cache.join(&pointer.version), &pointer.checksums)
    }

    #[test]
    fn open_retries_with_the_pointer_that_replaced_the_missing_version() {
        let cache = tempfile::tempdir().unwrap();
        let checksums = fixture_checksums();
        let moved_to = content_version(&checksums);
        install_fixture_version(cache.path(), &moved_to);
        write_pointer(cache.path(), &"a".repeat(64), &checksums);
        let mut calls = 0;
        let bundle = open_with_retry(cache.path(), |pointer| {
            calls += 1;
            if calls == 1 {
                write_pointer(cache.path(), &moved_to, &checksums);
            }
            open_pointed(cache.path(), pointer)
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert!(bundle.lookup_asn(4_242_420_001).is_some());
    }

    #[test]
    fn open_surfaces_the_error_when_the_pointer_did_not_move() {
        let cache = tempfile::tempdir().unwrap();
        write_pointer(cache.path(), &"a".repeat(64), &fixture_checksums());
        let mut calls = 0;
        let error = open_with_retry(cache.path(), |pointer| {
            calls += 1;
            open_pointed(cache.path(), pointer)
        })
        .err()
        .unwrap();
        assert_eq!(calls, 1);
        assert!(error.is_not_found());
    }

    #[test]
    fn open_gives_up_after_three_attempts() {
        let cache = tempfile::tempdir().unwrap();
        let checksums = fixture_checksums();
        let versions = ["a", "b", "c", "d"].map(|digit| digit.repeat(64));
        write_pointer(cache.path(), &versions[0], &checksums);
        let mut calls = 0;
        let error = open_with_retry(cache.path(), |pointer| {
            calls += 1;
            write_pointer(cache.path(), &versions[calls], &checksums);
            open_pointed(cache.path(), pointer)
        })
        .err()
        .unwrap();
        assert_eq!(calls, OPEN_ATTEMPTS);
        assert!(error.is_not_found());
    }

    #[test]
    fn open_does_not_retry_unrelated_errors() {
        let cache = tempfile::tempdir().unwrap();
        write_pointer(cache.path(), &"a".repeat(64), &fixture_checksums());
        let mut calls = 0;
        let error = open_with_retry(cache.path(), |_| {
            calls += 1;
            Err(Error::LockTimeout)
        })
        .err()
        .unwrap();
        assert_eq!(calls, 1);
        assert!(matches!(error, Error::LockTimeout));
    }
}
