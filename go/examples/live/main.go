// Command live checks the SDK against a public DN42 IPDB release.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	ipdb "github.com/bird-chinese-community/DN42-IPDB-SDK/go"
)

func main() {
	if err := run(); err != nil {
		panic(err)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return errors.New("pass an isolated cache directory")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	update, err := ipdb.Download(ctx, ipdb.DownloadOptions{
		CacheDir: os.Args[1],
		BaseURL:  os.Getenv("DN42_IPDB_RELEASE_URL"),
	})
	if err != nil {
		return err
	}
	database, err := ipdb.OpenCached(os.Args[1])
	if err != nil {
		return err
	}
	defer database.Close()
	ip, err := database.Lookup("172.23.33.0")
	if err != nil {
		return err
	}
	match, found := ip.Records["asn"]
	if !found || fmt.Sprint(match.Data["autonomous_system_number"]) != "4242420803" {
		return errors.New("public ASN lookup did not match the release contract")
	}
	asn, found := database.LookupASN(4242420803)
	if !found || database.ReleaseMetadata()["schema_version"] != "2" {
		return errors.New("public sidecars did not match the release contract")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"update": update,
		"ip":     ip,
		"asn":    asn,
	})
}
