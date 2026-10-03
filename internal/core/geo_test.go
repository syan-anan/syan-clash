package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vvpn/internal/logbus"
)

func TestMihomoConfigPointsGeoDownloadsAtAMirror(t *testing.T) {
	doc, err := EmitMihomo(sampleProfile())
	if err != nil {
		t.Fatalf("EmitMihomo: %v", err)
	}
	text := yamlEmit(doc)
	for _, want := range []string{
		"geox-url:\n",
		"geo-auto-update: false\n",
		// The mirror order is measured, so the test follows it instead of
		// pinning one vendor.
		"  mmdb: " + DefaultMirrors[0] + GeoURLMMDB + "\n",
		"  geoip: " + DefaultMirrors[0] + GeoURLGeoIP + "\n",
		"  geosite: " + DefaultMirrors[0] + GeoURLGeoSite + "\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("mihomo config is missing %q\n%s", want, text)
		}
	}
}

func TestMihomoGeoURLsFollowTheConfiguredMirror(t *testing.T) {
	p := sampleProfile()
	p.GeoMirror = "https://my.mirror" // no trailing slash on purpose
	doc, err := EmitMihomo(p)
	if err != nil {
		t.Fatalf("EmitMihomo: %v", err)
	}
	text := yamlEmit(doc)
	if !strings.Contains(text, "https://my.mirror/"+GeoURLMMDB) {
		t.Errorf("configured mirror was not used:\n%s", text)
	}
	if strings.Contains(text, DefaultMirrors[0]) {
		t.Errorf("built-in mirror leaked into a config that named its own:\n%s", text)
	}
}

func writeSized(t *testing.T, path string, head []byte, size int) {
	t.Helper()
	buf := make([]byte, size)
	copy(buf, head)
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestGeoFileValid(t *testing.T) {
	dir := t.TempDir()
	mmdb := GeoAsset{Name: "x.metadb", Kind: "mmdb", MinSize: 8}
	dat := GeoAsset{Name: "x.dat", Kind: "dat", MinSize: 8}

	cases := []struct {
		name  string
		asset GeoAsset
		head  []byte
		size  int
		want  bool
	}{
		{"metadb", mmdb, []byte{0x00, 0x00, 0x01, 0x15, 0x6a, 0x55, 0x00, 0x00}, 64, true},
		{"maxmind", mmdb, []byte{0xab, 0xcd, 0xef, 'M', 'a', 'x', 'M', 'i'}, 64, true},
		{"v2ray dat", dat, []byte{0x0a, 0xcc, 0x06, 0x0a, 0x04, 0x48, 0x53, 0x42}, 64, true},
		{"html error page", mmdb, []byte("<!DOCTYPE html>"), 64, false},
		{"truncated", mmdb, []byte{0x00, 0x00, 0x01, 0x15}, 4, false},
		{"wrong magic", dat, []byte{0x0b, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, 64, false},
	}
	for _, tc := range cases {
		path := filepath.Join(dir, tc.name)
		writeSized(t, path, tc.head, tc.size)
		if got := geoFileValid(path, tc.asset); got != tc.want {
			t.Errorf("geoFileValid(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
	if geoFileValid(filepath.Join(dir, "missing"), mmdb) {
		t.Error("a missing file must not count as valid")
	}
}

func TestGeoStatusTracksEveryAsset(t *testing.T) {
	s := NewSupervisor(t.TempDir(), logbus.New(64, logbus.LevelInfo))
	dir := s.Dir("mihomo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, a := range GeoAssetsFor["mihomo"] {
		if a.MinSize < 1<<20 {
			t.Fatalf("%s has an implausibly small minimum size: %d", a.Name, a.MinSize)
		}
	}
	if s.GeoReady("mihomo") {
		t.Error("an empty core directory must not report ready")
	}
	status := s.GeoStatus("mihomo")
	if len(status) != len(GeoAssetsFor["mihomo"]) {
		t.Fatalf("status lists %d files, want %d", len(status), len(GeoAssetsFor["mihomo"]))
	}
	for _, f := range status {
		if f.OK || f.Present {
			t.Errorf("%s: present=%v ok=%v, want both false on an empty directory", f.Name, f.Present, f.OK)
		}
	}

	// Fill every file: the core is now ready, and nothing is reported as
	// missing any more.
	for _, a := range GeoAssetsFor["mihomo"] {
		head := []byte{0x0a}
		if a.Kind == "mmdb" {
			head = []byte{0x00, 0x00, 0x01, 0x15}
		}
		writeSized(t, filepath.Join(dir, a.Name), head, int(a.MinSize))
	}
	if !s.GeoReady("mihomo") {
		t.Error("a complete geodata set should report ready")
	}
	for _, f := range s.GeoStatus("mihomo") {
		if !f.OK || !f.Present {
			t.Errorf("%s: present=%v ok=%v, want both true", f.Name, f.Present, f.OK)
		}
	}

	// Optional databases never gate readiness: a core missing the ASN database
	// that nothing reads must still be able to start.
	var optional []string
	for _, a := range GeoAssetsFor["mihomo"] {
		if a.Optional {
			optional = append(optional, a.Name)
		}
	}
	if len(optional) == 0 {
		t.Fatal("expected some geodata to be optional; a first run must not fetch 40 MB")
	}
	for _, name := range optional {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatalf("remove %s: %v", name, err)
		}
	}
	if !s.GeoReady("mihomo") {
		t.Error("removing an optional database must not make the core unready")
	}
	fetched, err := s.EnsureGeo(context.Background(), "mihomo", "")
	if err != nil || len(fetched) != 0 {
		t.Errorf("EnsureGeo must not download optional databases, got %v %v", fetched, err)
	}

	// A core that needs no geodata is a no-op, never an error.
	fetched, err = s.EnsureGeo(context.Background(), "sing-box", "")
	if err != nil || len(fetched) != 0 {
		t.Errorf("EnsureGeo for a core without geodata = (%v, %v), want no-op", fetched, err)
	}
}

func TestGeoHintOnlyFiresOnGeoFailures(t *testing.T) {
	geoSaid := "level=error msg=\"can't initial GeoIP: can't download MMDB: context deadline exceeded\"\nrules[514] [GEOIP,CN,DIRECT] error"
	if GeoHint("mihomo", geoSaid) == "" {
		t.Error("a geo download failure must produce a hint")
	}
	if GeoHint("mihomo", "unsupported rule type: FOO") != "" {
		t.Error("an unrelated failure must not produce a geo hint")
	}
	if GeoHint("xray", geoSaid) != "" {
		t.Error("a core that needs no geodata must not produce a geo hint")
	}
}
