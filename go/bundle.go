// Package ipdb reads BIRDCC DN42 IPDB release bundles locally.
package ipdb

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Record retains standard GeoIP2 fields and the DN42 extension map.
type Record map[string]any

// Match is the record of one database for a looked-up address. Network is the
// canonical CIDR of the matched network in the address family of the lookup.
type Match struct {
	Network      string `json:"network"`
	PrefixLength int    `json:"prefix_length"`
	Data         Record `json:"data"`
}

// Result holds the canonical address and the matches of every database with a record.
type Result struct {
	IP      string           `json:"ip"`
	Records map[string]Match `json:"records"`
}

// Observation is one scoped measurement or registry claim about a member network.
type Observation struct {
	Target     string  `json:"target"`
	ASN        *uint32 `json:"asn,omitempty"`
	Kind       string  `json:"kind"`
	Value      *string `json:"value,omitempty"`
	Status     string  `json:"status"`
	Method     string  `json:"method"`
	Source     string  `json:"source"`
	Authority  string  `json:"authority"`
	ObservedAt string  `json:"observed_at"`
}

// RegisteredCountry is a registry registration claim of a member allocation.
type RegisteredCountry struct {
	ISOCode string            `json:"iso_code"`
	Names   map[string]string `json:"names"`
}

// AsnInfo summarizes registration claims and observations for the member
// prefixes of one ASN. Network types do not classify the whole AS.
type AsnInfo struct {
	ASN                  uint32              `json:"asn"`
	AsName               *string             `json:"as_name,omitempty"`
	RegisteredCountries  []RegisteredCountry `json:"registered_countries"`
	Prefixes             []string            `json:"prefixes"`
	ObservedNetworkTypes []string            `json:"observed_network_types"`
	Observations         []Observation       `json:"observations"`
}

// RouteWindow is the observation time of the oldest and newest route in a release.
type RouteWindow struct {
	First string `json:"first"`
	Last  string `json:"last"`
}

// ReleaseMetadata is the release metadata document. Optional fields are empty
// when absent and a JSON null in any of them is rejected; Raw holds the
// complete decoded document, numbers as json.Number.
type ReleaseMetadata struct {
	SchemaVersion       string            `json:"schema_version"`
	ReleaseRepository   string            `json:"release_repository"`
	Copyright           string            `json:"copyright"`
	ReleaseTag          string            `json:"release_tag,omitempty"`
	ReleaseURL          string            `json:"release_url,omitempty"`
	BuiltAt             string            `json:"built_at,omitempty"`
	RegistryCommit      string            `json:"registry_commit,omitempty"`
	RegistryCommittedAt string            `json:"registry_committed_at,omitempty"`
	RouteObservedAt     *RouteWindow      `json:"route_observed_at,omitempty"`
	DatabaseTypes       map[string]string `json:"database_types,omitempty"`
	Raw                 map[string]any    `json:"-"`
}

// Database holds a validated bundle in memory.
type Database struct {
	readers  map[string]*maxminddb.Reader
	asns     []AsnInfo
	asnIndex map[uint32]int
	release  ReleaseMetadata
}

// Open reads the seven bundle files of a directory once and validates them.
func Open(directory string) (*Database, error) {
	files, err := readBundleFiles(directory)
	if err != nil {
		return nil, err
	}
	return parseBundle(files)
}

func readBundleFiles(directory string) (map[string][]byte, error) {
	files := make(map[string][]byte, len(bundleFiles))
	for _, name := range bundleFiles {
		data, err := readBounded(filepath.Join(directory, name), fileLimit(name))
		if errors.Is(err, os.ErrNotExist) {
			return nil, invalidBundle(name, err)
		}
		if err != nil {
			return nil, fmt.Errorf("read bundle file %s: %w", name, err)
		}
		files[name] = data
	}
	return files, nil
}

func parseBundle(files map[string][]byte) (*Database, error) {
	release, err := parseRelease(files[metadataFile])
	if err != nil {
		return nil, err
	}
	asns, err := parseASNIndex(files[asnIndexFile])
	if err != nil {
		return nil, err
	}
	readers, err := openReaders(files, release.DatabaseTypes)
	if err != nil {
		return nil, err
	}
	index := make(map[uint32]int, len(asns))
	for position, info := range asns {
		index[info.ASN] = position
	}
	return &Database{readers: readers, asns: asns, asnIndex: index, release: release}, nil
}

func parseRelease(data []byte) (ReleaseMetadata, error) {
	var release ReleaseMetadata
	if err := json.Unmarshal(data, &release); err != nil {
		return ReleaseMetadata{}, invalidBundle(metadataFile, err)
	}
	switch {
	case release.SchemaVersion != schema:
		return ReleaseMetadata{}, invalidBundleReason(metadataFile, "schema_version must be %q", schema)
	case release.ReleaseRepository == "" || release.Copyright == "":
		return ReleaseMetadata{}, invalidBundleReason(metadataFile, "release_repository and copyright must not be empty")
	}
	return release, nil
}

func parseASNIndex(data []byte) ([]AsnInfo, error) {
	var index struct {
		SchemaVersion string             `json:"schema_version"`
		ASNs          map[string]AsnInfo `json:"asns"`
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, invalidBundle(asnIndexFile, err)
	}
	if index.SchemaVersion != schema {
		return nil, invalidBundleReason(asnIndexFile, "schema_version must be %q", schema)
	}
	if index.ASNs == nil {
		return nil, invalidBundleReason(asnIndexFile, "asns must be an object")
	}
	asns := make([]AsnInfo, 0, len(index.ASNs))
	for key, info := range index.ASNs {
		if err := validateASN(key, info); err != nil {
			return nil, invalidBundle(asnIndexFile, err)
		}
		asns = append(asns, info)
	}
	slices.SortFunc(asns, func(a, b AsnInfo) int { return compareASN(a.ASN, b.ASN) })
	return asns, nil
}

func compareASN(a, b uint32) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func validateASN(key string, info AsnInfo) error {
	if key != strconv.FormatUint(uint64(info.ASN), 10) {
		return fmt.Errorf("key %q does not match asn %d", key, info.ASN)
	}
	return nil
}

// openReaders opens the four databases and checks their database_type against
// the required type and the types declared in metadata.json.
func openReaders(files map[string][]byte, declared map[string]string) (map[string]*maxminddb.Reader, error) {
	readers := make(map[string]*maxminddb.Reader, len(databases))
	for _, database := range databases {
		reader, err := openReader(database.file, database.kind, files[database.file], declared)
		if err != nil {
			closeReaders(readers)
			return nil, err
		}
		readers[database.key] = reader
	}
	return readers, nil
}

func openReader(file, kind string, data []byte, declared map[string]string) (*maxminddb.Reader, error) {
	reader, err := maxminddb.OpenBytes(data)
	if err != nil {
		return nil, invalidBundle(file, err)
	}
	actual := reader.Metadata.DatabaseType
	if actual != kind {
		_ = reader.Close()
		return nil, invalidBundleReason(file, "database_type is %q, expected %q", actual, kind)
	}
	if listed, found := declared[file]; found && listed != actual {
		_ = reader.Close()
		return nil, invalidBundleReason(metadataFile, "database_types lists %q for %s, database_type is %q", listed, file, actual)
	}
	return reader, nil
}

func closeReaders(readers map[string]*maxminddb.Reader) {
	for _, reader := range readers {
		_ = reader.Close()
	}
}

// Lookup performs no network requests. Missing networks are absent from Records.
func (db *Database) Lookup(input string) (Result, error) {
	ip, err := netip.ParseAddr(input)
	if err != nil || ip.Zone() != "" {
		return Result{}, fmt.Errorf("%w: %q", ErrInvalidAddress, input)
	}
	ip = ip.Unmap()
	output := Result{IP: ip.String(), Records: make(map[string]Match)}
	for key, reader := range db.readers {
		match, found, err := lookupMatch(reader, ip)
		if err != nil {
			return Result{}, fmt.Errorf("lookup %s: %w", key, err)
		}
		if found {
			output.Records[key] = match
		}
	}
	return output, nil
}

func lookupMatch(reader *maxminddb.Reader, ip netip.Addr) (Match, bool, error) {
	result := reader.Lookup(ip)
	if err := result.Err(); err != nil {
		return Match{}, false, err
	}
	if !result.Found() {
		return Match{}, false, nil
	}
	var record Record
	if err := result.Decode(&record); err != nil {
		return Match{}, false, fmt.Errorf("decode record: %w", err)
	}
	if len(record) == 0 {
		return Match{}, false, nil
	}
	prefix := result.Prefix()
	return Match{Network: prefix.Masked().String(), PrefixLength: prefix.Bits(), Data: record}, true, nil
}

// Metadata returns the MMDB metadata of each database key.
func (db *Database) Metadata() map[string]maxminddb.Metadata {
	metadata := make(map[string]maxminddb.Metadata, len(db.readers))
	for key, reader := range db.readers {
		metadata[key] = reader.Metadata
	}
	return metadata
}

// LookupASN returns observations for member prefixes; these do not classify an entire AS.
func (db *Database) LookupASN(asn uint32) (AsnInfo, bool) {
	position, found := db.asnIndex[asn]
	if !found {
		return AsnInfo{}, false
	}
	return db.asns[position], true
}

// ASNs returns every AsnInfo ordered by ASN ascending.
func (db *Database) ASNs() []AsnInfo { return slices.Clone(db.asns) }

// ReleaseMetadata returns the typed release metadata document.
func (db *Database) ReleaseMetadata() ReleaseMetadata { return db.release }

// Close releases the database readers.
func (db *Database) Close() error {
	var failures []error
	for _, reader := range db.readers {
		failures = append(failures, reader.Close())
	}
	return errors.Join(failures...)
}
