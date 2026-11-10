//! Read BIRDCC DN42 IPDB release bundles and update a verified local cache.

use std::collections::BTreeMap;
use std::fs::{self, File, TryLockError};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use maxminddb::Reader;
use reqwest::{Url, blocking::Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::{Builder, NamedTempFile};
use thiserror::Error;

pub const DEFAULT_RELEASE_URL: &str =
    "https://github.com/bird-chinese-community/DN42-IPDB-Releases/releases/latest/download/";
pub const MAX_DATABASE_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);
const FILES: [&str; 7] = [
    "DN42-IPDB-Country.mmdb",
    "DN42-IPDB-City.mmdb",
    "DN42-IPDB-ASN.mmdb",
    "DN42-IPDB-Connection-Type.mmdb",
    "asn-index.json",
    "metadata.json",
    "LICENSE-Unicode.txt",
];
const DATABASES: [(&str, &str, &str); 4] = [
    ("country", "DN42-IPDB-Country.mmdb", "DN42-GeoIP2-Country"),
    ("city", "DN42-IPDB-City.mmdb", "DN42-GeoIP2-City"),
    ("asn", "DN42-IPDB-ASN.mmdb", "DN42-GeoLite2-ASN"),
    (
        "connection_type",
        "DN42-IPDB-Connection-Type.mmdb",
        "DN42-GeoIP2-Connection-Type",
    ),
];

#[derive(Debug, Error)]
pub enum Error {
    #[error("filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("release request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("invalid release JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid MaxMind database: {0}")]
    Maxmind(#[from] maxminddb::MaxMindDbError),
    #[error("invalid DN42 bundle: {0}")]
    Invalid(String),
    #[error("DN42 update was cancelled")]
    Cancelled,
    #[error("DN42 update deadline expired")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Observation {
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub as_name: Option<String>,
    pub registered_countries: Vec<RegisteredCountry>,
    pub prefixes: Vec<String>,
    pub observed_network_types: Vec<String>,
    pub observations: Vec<Observation>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Match {
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

/// All four readers and the ASN index are owned in memory; lookups perform no I/O.
pub struct Bundle {
    readers: BTreeMap<String, Reader<Vec<u8>>>,
    asns: BTreeMap<String, AsnInfo>,
    release: Value,
}

impl Bundle {
    pub fn open(directory: impl AsRef<Path>) -> Result<Self> {
        let directory = directory.as_ref();
        read_bounded(&directory.join("LICENSE-Unicode.txt"), MAX_DATABASE_BYTES)?;
        let index: AsnIndex = serde_json::from_slice(&read_bounded(
            &directory.join("asn-index.json"),
            MAX_DATABASE_BYTES,
        )?)?;
        if index.schema_version != "2" {
            return Err(Error::Invalid("ASN index requires schema version 2".into()));
        }
        for (key, value) in &index.asns {
            if key != &value.asn.to_string() {
                return Err(Error::Invalid(format!(
                    "ASN index key does not match its record: {key}"
                )));
            }
        }
        let release: Value = serde_json::from_slice(&read_bounded(
            &directory.join("metadata.json"),
            MAX_DATABASE_BYTES,
        )?)?;
        if release["schema_version"] != "2"
            || ["release_repository", "copyright"]
                .iter()
                .any(|key| release[*key].as_str().is_none_or(str::is_empty))
        {
            return Err(Error::Invalid(
                "release metadata requires schema version 2, repository and copyright".into(),
            ));
        }
        let mut readers = BTreeMap::new();
        for (key, file, expected) in DATABASES {
            let reader =
                Reader::from_source(read_bounded(&directory.join(file), MAX_DATABASE_BYTES)?)?;
            if reader.metadata().database_type != expected {
                return Err(Error::Invalid(format!(
                    "{file}: expected {expected} database"
                )));
            }
            if let Some(declared) = release
                .get("database_types")
                .and_then(|types| types.get(file))
                && declared.as_str() != Some(reader.metadata().database_type.as_str())
            {
                return Err(Error::Invalid(format!(
                    "metadata database type mismatch: {file}"
                )));
            }
            readers.insert(key.into(), reader);
        }
        Ok(Self {
            readers,
            asns: index.asns,
            release,
        })
    }

    pub fn lookup_ip(&self, ip: IpAddr) -> Result<IpLookup> {
        let ip = match ip {
            IpAddr::V6(address) => address.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            _ => ip,
        };
        let mut records = BTreeMap::new();
        for (key, reader) in &self.readers {
            let result = reader.lookup(ip)?;
            if let Some(data) = result.decode::<Value>()?
                && data.as_object().is_some_and(|value| !value.is_empty())
            {
                records.insert(
                    key.clone(),
                    Match {
                        prefix_length: result.network()?.prefix(),
                        data,
                    },
                );
            }
        }
        Ok(IpLookup { ip, records })
    }

    pub fn lookup_asn(&self, asn: u32) -> Option<&AsnInfo> {
        self.asns.get(&asn.to_string())
    }

    pub fn release_metadata(&self) -> &Value {
        &self.release
    }

    pub fn database_metadata(&self) -> BTreeMap<&str, &maxminddb::Metadata> {
        self.readers
            .iter()
            .map(|(key, reader)| (key.as_str(), reader.metadata()))
            .collect()
    }
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

#[derive(Deserialize, Serialize)]
struct Pointer {
    version: String,
    checksums: BTreeMap<String, String>,
}

pub struct Update {
    pub directory: PathBuf,
    pub changed: bool,
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
            return Err(Error::Invalid("cache directory is required".into()));
        }
        let mut base_url = Url::parse(base_url)
            .map_err(|error| Error::Invalid(format!("release URL: {error}")))?;
        validate_url(&base_url, None)?;
        if !base_url.path().ends_with('/') {
            base_url.set_path(&format!("{}/", base_url.path()));
        }
        Ok(Self {
            directory: cache_root.as_ref().join("rust").join("v2"),
            base_url,
            timeout: TIMEOUT,
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Result<Self> {
        if timeout.is_zero() || timeout > TIMEOUT {
            return Err(Error::Invalid(
                "timeout must be greater than zero and at most 30 seconds".into(),
            ));
        }
        self.timeout = timeout;
        Ok(self)
    }

    pub fn open_cached(&self) -> Result<Bundle> {
        let cancellation = Cancellation::default();
        let _guard = lock_cache(
            &self.directory,
            Instant::now() + self.timeout,
            &cancellation,
        )?;
        let pointer = read_pointer(&self.directory)?;
        verify_bundle(&self.directory.join(pointer.version), &pointer.checksums)
    }

    pub fn refresh(&self) -> Result<Update> {
        self.refresh_with_cancel(&Cancellation::default())
    }

    pub fn refresh_with_cancel(&self, cancellation: &Cancellation) -> Result<Update> {
        let deadline = Instant::now() + self.timeout;
        let _guard = lock_cache(&self.directory, deadline, cancellation)?;
        let redirect_origin = self.base_url.clone();
        let client = Client::builder()
            .redirect(Policy::custom(move |attempt| {
                if attempt.previous().len() >= 10 {
                    return attempt.error("too many release redirects");
                }
                if let Err(error) = validate_url(attempt.url(), Some(&redirect_origin)) {
                    return attempt.error(error);
                }
                attempt.follow()
            }))
            .build()?;
        let manifest = fetch(
            &client,
            self.base_url
                .join("checksums.json")
                .map_err(|error| Error::Invalid(error.to_string()))?,
            MAX_MANIFEST_BYTES,
            deadline,
            cancellation,
        )?;
        let checksums: BTreeMap<String, String> = serde_json::from_slice(&manifest)?;
        validate_checksums(&checksums)?;
        let previous = match read_pointer(&self.directory) {
            Ok(pointer) => Some(pointer),
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if let Some(pointer) = &previous
            && FILES
                .iter()
                .all(|name| pointer.checksums.get(*name) == checksums.get(*name))
        {
            let directory = self.directory.join(&pointer.version);
            let bundle = verify_bundle(&directory, &checksums)?;
            cancellation.check(deadline)?;
            return Ok(Update {
                directory,
                changed: false,
                bundle,
            });
        }
        let stage = Builder::new()
            .prefix(".stage-")
            .tempdir_in(&self.directory)?;
        for file in FILES {
            let bytes = fetch(
                &client,
                self.base_url
                    .join(file)
                    .map_err(|error| Error::Invalid(error.to_string()))?,
                MAX_DATABASE_BYTES,
                deadline,
                cancellation,
            )?;
            if checksum(&bytes) != checksums[file] {
                return Err(Error::Invalid(format!("checksum mismatch: {file}")));
            }
            let mut output = File::create(stage.path().join(file))?;
            output.write_all(&bytes)?;
            output.sync_all()?;
        }
        let bundle = Bundle::open(stage.path())?;
        let required: BTreeMap<_, _> = FILES
            .iter()
            .map(|file| (*file, &checksums[*file]))
            .collect();
        let version = checksum(&serde_json::to_vec(&required)?);
        let directory = self.directory.join(&version);
        cancellation.check(deadline)?;
        let mut activation = ActivationGuard(None);
        if directory.exists() {
            verify_bundle(&directory, &checksums)?;
        } else {
            fs::rename(stage.path(), &directory)?;
            activation.0 = Some(directory.clone());
        }
        prune(
            &self.directory,
            &version,
            previous.as_ref().map(|value| value.version.as_str()),
        )?;
        let mut pending = NamedTempFile::new_in(&self.directory)?;
        serde_json::to_writer(&mut pending, &Pointer { version, checksums })?;
        pending.as_file().sync_all()?;
        cancellation.check(deadline)?;
        pending
            .persist(self.directory.join("current.json"))
            .map_err(|error| Error::Io(error.error))?;
        activation.0 = None;
        Ok(Update {
            directory,
            changed: true,
            bundle,
        })
    }
}

struct ActivationGuard(Option<PathBuf>);

impl Drop for ActivationGuard {
    fn drop(&mut self) {
        if let Some(directory) = &self.0 {
            let _ = fs::remove_dir_all(directory);
        }
    }
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(Error::Invalid(format!(
            "file size limit: {}",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(Error::Invalid(format!(
            "file size limit: {}",
            path.display()
        )));
    }
    Ok(bytes)
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

fn validate_checksums(checksums: &BTreeMap<String, String>) -> Result<()> {
    for file in FILES {
        if !checksums.get(file).is_some_and(|value| is_digest(value)) {
            return Err(Error::Invalid(format!(
                "missing or invalid checksum: {file}"
            )));
        }
    }
    Ok(())
}

fn read_pointer(cache: &Path) -> Result<Pointer> {
    let pointer: Pointer = serde_json::from_slice(&read_bounded(
        &cache.join("current.json"),
        MAX_MANIFEST_BYTES,
    )?)?;
    if !is_digest(&pointer.version) {
        return Err(Error::Invalid("invalid cache version".into()));
    }
    validate_checksums(&pointer.checksums)?;
    Ok(pointer)
}

fn verify_bundle(directory: &Path, checksums: &BTreeMap<String, String>) -> Result<Bundle> {
    validate_checksums(checksums)?;
    for file in FILES {
        if checksum(&read_bounded(&directory.join(file), MAX_DATABASE_BYTES)?) != checksums[file] {
            return Err(Error::Invalid(format!("cached checksum mismatch: {file}")));
        }
    }
    Bundle::open(directory)
}

fn validate_url(url: &Url, origin: Option<&Url>) -> Result<()> {
    if !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
        || (origin.is_none() && url.query().is_some())
        || url.fragment().is_some()
    {
        return Err(Error::Invalid("release URL must have a host and no credentials or fragment; base URLs cannot contain queries".into()));
    }
    if url.scheme() == "https" {
        return Ok(());
    }
    let loopback = url
        .host_str()
        .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    let same_origin = origin.is_none_or(|origin| {
        origin.scheme() == "http"
            && origin.host_str() == url.host_str()
            && origin.port_or_known_default() == url.port_or_known_default()
    });
    if url.scheme() == "http" && loopback && same_origin {
        return Ok(());
    }
    Err(Error::Invalid(
        "release URL requires HTTPS or same-origin loopback HTTP".into(),
    ))
}

fn fetch(
    client: &Client,
    url: Url,
    limit: usize,
    deadline: Instant,
    cancellation: &Cancellation,
) -> Result<Vec<u8>> {
    cancellation.check(deadline)?;
    let mut response = client
        .get(url)
        .timeout(deadline.saturating_duration_since(Instant::now()))
        .send()?
        .error_for_status()?;
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(Error::Invalid("release response size limit".into()));
    }
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        cancellation.check(deadline)?;
        let count = response.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        if bytes.len() + count > limit {
            return Err(Error::Invalid("release response size limit".into()));
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    Ok(bytes)
}

fn lock_cache(directory: &Path, deadline: Instant, cancellation: &Cancellation) -> Result<File> {
    fs::create_dir_all(directory)?;
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join(".update.lock"))?;
    loop {
        cancellation.check(deadline)?;
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) => thread::sleep(Duration::from_millis(20)),
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }
    }
}

fn prune(cache: &Path, current: &str, previous: Option<&str>) -> Result<()> {
    for entry in fs::read_dir(cache)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !is_digest(&name)
            || name == current
            || previous == Some(name.as_ref())
            || !entry.file_type()?.is_dir()
        {
            continue;
        }
        let entries = fs::read_dir(entry.path())?.collect::<std::io::Result<Vec<_>>>()?;
        if entries.len() == FILES.len()
            && entries.iter().all(|item| {
                item.file_type().is_ok_and(|kind| kind.is_file())
                    && FILES.iter().any(|file| item.file_name() == *file)
            })
        {
            fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}
