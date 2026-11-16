package ipdb

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestLookupCanonicalAddresses(t *testing.T) {
	db, err := Open("testdata")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, test := range []struct {
		input, ip, network string
		prefix             int
	}{
		{"172.20.0.1", "172.20.0.1", "172.20.0.1/32", 32},
		{"::ffff:172.20.0.1", "172.20.0.1", "172.20.0.1/32", 32},
		{"::FFFF:AC14:1", "172.20.0.1", "172.20.0.1/32", 32},
		{"fd42:1234::1", "fd42:1234::1", "fd42:1234::1/128", 128},
		{"FD42:1234::1", "fd42:1234::1", "fd42:1234::1/128", 128},
	} {
		result, err := db.Lookup(test.input)
		if err != nil {
			t.Fatalf("%s: %v", test.input, err)
		}
		if result.IP != test.ip || len(result.Records) != len(databases) {
			t.Fatalf("%s: %#v", test.input, result)
		}
		for key, match := range result.Records {
			if match.Network != test.network || match.PrefixLength != test.prefix {
				t.Fatalf("%s %s: %#v", test.input, key, match)
			}
		}
	}
}

func TestLookupRejectsInvalidAddresses(t *testing.T) {
	db, err := Open("testdata")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, input := range []string{"", "bad-ip", "172.20.0.256", "fe80::1%eth0", "172.20.0.1%1", "172.20.0.1/32"} {
		if _, err := db.Lookup(input); !errors.Is(err, ErrInvalidAddress) {
			t.Errorf("%q: %v", input, err)
		}
	}
}

func TestASNsAreOrdered(t *testing.T) {
	directory := copyBundle(t, func(files map[string][]byte) {
		files[asnIndexFile] = editJSON(t, files[asnIndexFile], func(document map[string]any) {
			asns := document["asns"].(map[string]any)
			template := asns["4242420001"].(map[string]any)
			for key, asn := range map[string]float64{"64512": 64512, "4294967295": 4294967295, "4242420000": 4242420000} {
				entry := map[string]any{}
				for field, value := range template {
					entry[field] = value
				}
				entry["asn"] = asn
				asns[key] = entry
			}
		})
	})
	db, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var order []uint32
	for _, info := range db.ASNs() {
		order = append(order, info.ASN)
	}
	if !slices.Equal(order, []uint32{64512, 4242420000, 4242420001, 4294967295}) {
		t.Fatalf("ASN order: %v", order)
	}
	if info, found := db.LookupASN(4294967295); !found || info.ASN != 4294967295 {
		t.Fatalf("max ASN: %#v", info)
	}
}

func TestTypedReleaseMetadata(t *testing.T) {
	directory := copyBundle(t, func(files map[string][]byte) {
		files[metadataFile] = editJSON(t, files[metadataFile], func(document map[string]any) {
			document["release_tag"] = "v2026.1"
			document["route_observed_at"] = map[string]string{"first": "2026-11-15T07:43:11Z", "last": "2026-11-15T10:59:05Z"}
		})
	})
	db, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	release := db.ReleaseMetadata()
	if release.ReleaseTag != "v2026.1" || release.Raw["release_tag"] != "v2026.1" {
		t.Fatalf("release tag: %#v", release)
	}
	if release.RouteObservedAt == nil || release.RouteObservedAt.Last != "2026-11-15T10:59:05Z" {
		t.Fatalf("route window: %#v", release.RouteObservedAt)
	}
	if release.BuiltAt != "2023-11-14T22:13:20Z" || release.DatabaseTypes["DN42-IPDB-ASN.mmdb"] != "DN42-GeoLite2-ASN" {
		t.Fatalf("typed fields: %#v", release)
	}
	if release.Raw["publisher"] != "BIRD Chinese Community" {
		t.Fatalf("unknown keys must stay in Raw: %#v", release.Raw)
	}
}

func TestInvalidBundles(t *testing.T) {
	for name, mutate := range map[string]func(files map[string][]byte){
		"metadata schema version": func(files map[string][]byte) {
			files[metadataFile] = editJSON(t, files[metadataFile], func(d map[string]any) { d["schema_version"] = "1" })
		},
		"metadata repository": func(files map[string][]byte) {
			files[metadataFile] = editJSON(t, files[metadataFile], func(d map[string]any) { d["release_repository"] = "" })
		},
		"metadata not an object": func(files map[string][]byte) { files[metadataFile] = []byte(`[]`) },
		"database types null": func(files map[string][]byte) {
			files[metadataFile] = editJSON(t, files[metadataFile], func(d map[string]any) { d["database_types"] = nil })
		},
		"database types mismatch": func(files map[string][]byte) {
			files[metadataFile] = editJSON(t, files[metadataFile], func(d map[string]any) {
				d["database_types"] = map[string]any{"DN42-IPDB-City.mmdb": "DN42-GeoIP2-Country"}
			})
		},
		"asn index key": func(files map[string][]byte) {
			files[asnIndexFile] = editJSON(t, files[asnIndexFile], func(d map[string]any) {
				asns := d["asns"].(map[string]any)
				asns["4242420002"] = asns["4242420001"]
				delete(asns, "4242420001")
			})
		},
		"asn index schema": func(files map[string][]byte) {
			files[asnIndexFile] = editJSON(t, files[asnIndexFile], func(d map[string]any) { d["schema_version"] = "1" })
		},
		"asn index shape": func(files map[string][]byte) {
			files[asnIndexFile] = editJSON(t, files[asnIndexFile], func(d map[string]any) { d["asns"] = []any{} })
		},
		"asn name null": func(files map[string][]byte) {
			files[asnIndexFile] = editJSON(t, files[asnIndexFile], func(d map[string]any) {
				d["asns"].(map[string]any)["4242420001"].(map[string]any)["as_name"] = nil
			})
		},
		"release tag null": func(files map[string][]byte) {
			files[metadataFile] = editJSON(t, files[metadataFile], func(d map[string]any) { d["release_tag"] = nil })
		},
		"route window null": func(files map[string][]byte) {
			files[metadataFile] = editJSON(t, files[metadataFile], func(d map[string]any) { d["route_observed_at"] = nil })
		},
		"route window empty": func(files map[string][]byte) {
			files[metadataFile] = editJSON(t, files[metadataFile], func(d map[string]any) { d["route_observed_at"] = map[string]any{} })
		},
		"route window first null": func(files map[string][]byte) {
			files[metadataFile] = editJSON(t, files[metadataFile], func(d map[string]any) {
				d["route_observed_at"] = map[string]any{"first": nil, "last": "2026-11-15T10:59:05Z"}
			})
		},
		"route window last missing": func(files map[string][]byte) {
			files[metadataFile] = editJSON(t, files[metadataFile], func(d map[string]any) {
				d["route_observed_at"] = map[string]any{"first": "2026-11-15T07:43:11Z"}
			})
		},
		"database types value null": func(files map[string][]byte) {
			files[metadataFile] = editJSON(t, files[metadataFile], func(d map[string]any) {
				d["database_types"] = map[string]any{"other.mmdb": nil}
			})
		},
		"prefixes element null": func(files map[string][]byte) {
			editASNRecord(t, files, func(r map[string]any) { r["prefixes"] = []any{nil} })
		},
		"network types element null": func(files map[string][]byte) {
			editASNRecord(t, files, func(r map[string]any) { r["observed_network_types"] = []any{nil} })
		},
		"country name null": func(files map[string][]byte) {
			editASNRecord(t, files, func(r map[string]any) {
				r["registered_countries"].([]any)[0].(map[string]any)["names"] = map[string]any{"en": nil}
			})
		},
		"observation without kind": func(files map[string][]byte) {
			editObservation(t, files, func(o map[string]any) { delete(o, "kind") })
		},
		"observation asn null": func(files map[string][]byte) {
			editObservation(t, files, func(o map[string]any) { o["asn"] = nil })
		},
		"observation value null": func(files map[string][]byte) {
			editObservation(t, files, func(o map[string]any) { o["value"] = nil })
		},
		"country without iso code": func(files map[string][]byte) {
			files[asnIndexFile] = editJSON(t, files[asnIndexFile], func(d map[string]any) {
				country := d["asns"].(map[string]any)["4242420001"].(map[string]any)["registered_countries"].([]any)[0].(map[string]any)
				delete(country, "iso_code")
			})
		},
		"asn record fields": func(files map[string][]byte) {
			files[asnIndexFile] = editJSON(t, files[asnIndexFile], func(d map[string]any) {
				delete(d["asns"].(map[string]any)["4242420001"].(map[string]any), "prefixes")
			})
		},
		"missing license":   func(files map[string][]byte) { delete(files, licenseFile) },
		"database mismatch": func(files map[string][]byte) { files["DN42-IPDB-City.mmdb"] = files["DN42-IPDB-ASN.mmdb"] },
		"database garbage":  func(files map[string][]byte) { files["DN42-IPDB-Country.mmdb"] = []byte("not a database") },
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			files := fixtureFiles(t)
			mutate(files)
			for file, data := range files {
				if err := os.WriteFile(filepath.Join(directory, file), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			db, err := Open(directory)
			if err == nil {
				_ = db.Close()
				t.Fatal("invalid bundle accepted")
			}
			if !errors.Is(err, ErrInvalidBundle) {
				t.Fatalf("expected invalid bundle error, got %v", err)
			}
		})
	}
}

// editASNRecord edits the record of ASN 4242420001.
func editASNRecord(t *testing.T, files map[string][]byte, edit func(record map[string]any)) {
	t.Helper()
	files[asnIndexFile] = editJSON(t, files[asnIndexFile], func(d map[string]any) {
		edit(d["asns"].(map[string]any)["4242420001"].(map[string]any))
	})
}

// editObservation edits the first observation of ASN 4242420001.
func editObservation(t *testing.T, files map[string][]byte, edit func(observation map[string]any)) {
	t.Helper()
	files[asnIndexFile] = editJSON(t, files[asnIndexFile], func(d map[string]any) {
		record := d["asns"].(map[string]any)["4242420001"].(map[string]any)
		edit(record["observations"].([]any)[0].(map[string]any))
	})
}

func TestEmptyRequiredStringsAreAccepted(t *testing.T) {
	directory := copyBundle(t, func(files map[string][]byte) {
		editObservation(t, files, func(o map[string]any) { o["authority"] = "" })
	})
	db, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
}

func TestInvalidBundleNamesFile(t *testing.T) {
	directory := copyBundle(t, func(files map[string][]byte) { delete(files, licenseFile) })
	if _, err := Open(directory); !errors.Is(err, ErrInvalidBundle) || !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), licenseFile) {
		t.Fatalf("error must name the missing file: %v", err)
	}
}

func TestOversizedAndIrregularFiles(t *testing.T) {
	directory := copyBundle(t, func(files map[string][]byte) {
		files[licenseFile] = make([]byte, MaxMetadataBytes+1)
	})
	if _, err := Open(directory); !errors.Is(err, ErrSizeLimit) {
		t.Fatalf("oversized sidecar: %v", err)
	}
	directory = copyBundle(t, func(files map[string][]byte) {})
	if err := os.Remove(filepath.Join(directory, licenseFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(directory, licenseFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(directory); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("directory in place of a file: %v", err)
	}
}
