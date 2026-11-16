package ipdb

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
)

// fieldRules names the keys of a JSON object that must be present and the keys
// that may be absent. A JSON null is rejected for every named key.
type fieldRules struct {
	required []string
	optional []string
}

var (
	observationRules = fieldRules{
		required: []string{"target", "kind", "status", "method", "source", "authority", "observed_at"},
		optional: []string{"asn", "value"},
	}
	countryRules = fieldRules{required: []string{"iso_code", "names"}}
	windowRules  = fieldRules{required: []string{"first", "last"}}
	asnInfoRules = fieldRules{
		required: []string{"asn", "registered_countries", "prefixes", "observed_network_types", "observations"},
		optional: []string{"as_name"},
	}
	releaseRules = fieldRules{
		required: []string{"schema_version", "release_repository", "copyright"},
		optional: []string{"release_tag", "release_url", "built_at", "registry_commit", "registry_committed_at", "route_observed_at", "database_types"},
	}
)

// decodeObject checks the presence and null rules of a JSON object and then
// decodes it into target, which must not implement json.Unmarshaler.
func decodeObject(name string, data []byte, target any, rules fieldRules) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if fields == nil {
		return fmt.Errorf("%s: must be an object", name)
	}
	for _, key := range rules.required {
		if _, found := fields[key]; !found {
			return fmt.Errorf("%s: %s is required", name, key)
		}
	}
	for key, raw := range fields {
		isNull := bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
		if isNull && (slices.Contains(rules.required, key) || slices.Contains(rules.optional, key)) {
			return fmt.Errorf("%s: %s must not be null", name, key)
		}
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// rejectNulls fails on a JSON null anywhere in a decoded document.
func rejectNulls(path string, value any) error {
	switch typed := value.(type) {
	case nil:
		return fmt.Errorf("%s must not be null", path)
	case map[string]any:
		for _, key := range slices.Sorted(maps.Keys(typed)) {
			if err := rejectNulls(path+"."+key, typed[key]); err != nil {
				return err
			}
		}
	case []any:
		for position, item := range typed {
			if err := rejectNulls(path+"["+strconv.Itoa(position)+"]", item); err != nil {
				return err
			}
		}
	}
	return nil
}

// rejectNullsIn decodes a JSON document and fails on a null anywhere inside it.
func rejectNullsIn(name string, data []byte) error {
	var document any
	if err := json.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return rejectNulls(name, document)
}

// UnmarshalJSON requires first and last and rejects null values.
func (w *RouteWindow) UnmarshalJSON(data []byte) error {
	type plain RouteWindow
	return decodeObject("route window", data, (*plain)(w), windowRules)
}

// UnmarshalJSON requires the fields of an observation and rejects null values.
func (o *Observation) UnmarshalJSON(data []byte) error {
	type plain Observation
	return decodeObject("observation", data, (*plain)(o), observationRules)
}

// UnmarshalJSON requires iso_code and names and rejects null values.
func (c *RegisteredCountry) UnmarshalJSON(data []byte) error {
	type plain RegisteredCountry
	return decodeObject("registered country", data, (*plain)(c), countryRules)
}

// UnmarshalJSON requires the list fields of an ASN record and rejects a null
// anywhere inside it.
func (a *AsnInfo) UnmarshalJSON(data []byte) error {
	if err := rejectNullsIn("asn record", data); err != nil {
		return err
	}
	type plain AsnInfo
	return decodeObject("asn record", data, (*plain)(a), asnInfoRules)
}

// UnmarshalJSON requires the mandatory release fields, rejects a null in any
// known field (nested values included) and keeps the complete document in Raw.
func (r *ReleaseMetadata) UnmarshalJSON(data []byte) error {
	type plain ReleaseMetadata
	var release plain
	if err := decodeObject("release metadata", data, &release, releaseRules); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&release.Raw); err != nil {
		return errors.Join(errors.New("release metadata: decode raw document"), err)
	}
	for _, key := range slices.Concat(releaseRules.required, releaseRules.optional) {
		if value, found := release.Raw[key]; found {
			if err := rejectNulls("release metadata."+key, value); err != nil {
				return err
			}
		}
	}
	*r = ReleaseMetadata(release)
	return nil
}
