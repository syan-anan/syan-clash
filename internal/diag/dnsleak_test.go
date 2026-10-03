package diag

import (
	"strings"
	"testing"
)

func TestParseDNSTargetClassifiesEveryEntryShape(t *testing.T) {
	cases := []struct {
		entry     string
		kind      string
		transport string
		host      string
		port      string
	}{
		{"1.1.1.1", "plain", "udp", "1.1.1.1", "53"},
		{"1.1.1.1:5353", "plain", "udp", "1.1.1.1", "5353"},
		{"223.5.5.5", "plain", "udp", "223.5.5.5", "53"},
		{"[2606:4700:4700::1111]", "plain", "udp", "2606:4700:4700::1111", "53"},
		{"https://dns.google/dns-query", "doh", "https", "dns.google", "443"},
		{"https://223.5.5.5/dns-query", "doh", "https", "223.5.5.5", "443"},
		{"tls://8.8.8.8:853", "dot", "tls", "8.8.8.8", "853"},
		{"tls://8.8.8.8", "dot", "tls", "8.8.8.8", "853"},
		{"dot://dns.quad9.net", "dot", "tls", "dns.quad9.net", "853"},
		{"quic://dns.adguard.com", "doq", "quic", "dns.adguard.com", "853"},
		{"dhcp://auto", "dhcp", "dhcp", "", ""},
		{"system", "system", "system", "", ""},
		{"local", "system", "system", "", ""},
	}
	for _, c := range cases {
		got := parseDNSTarget(c.entry)
		if got.Kind != c.kind || got.Transport != c.transport || got.Host != c.host || got.Port != c.port {
			t.Errorf("parseDNSTarget(%q) = %+v, want kind=%s transport=%s host=%s port=%s",
				c.entry, got, c.kind, c.transport, c.host, c.port)
		}
	}
}

func TestParseDNSTargetQueryability(t *testing.T) {
	queryable := []string{"1.1.1.1", "https://dns.google/dns-query", "tls://1.1.1.1"}
	for _, e := range queryable {
		if !parseDNSTarget(e).queryable() {
			t.Errorf("%s should be askable", e)
		}
	}
	for _, e := range []string{"system", "local", "dhcp://auto", "quic://dns.adguard.com"} {
		if parseDNSTarget(e).queryable() {
			t.Errorf("%s has no transport this client speaks yet", e)
		}
	}
}

func TestAssessDNSTurnsFactsIntoAVerdict(t *testing.T) {
	cases := []struct {
		name string
		in   DNSLeakEntry
		tun  bool
		want string
	}{
		{"poisoned beats everything", DNSLeakEntry{Kind: "doh", Poisoned: true}, true, riskLeak},
		{"system resolver without tunnel", DNSLeakEntry{Kind: "system"}, false, riskLeak},
		{"system resolver under a tunnel", DNSLeakEntry{Kind: "system"}, true, riskOK},
		{"lan resolver without tunnel", DNSLeakEntry{Kind: "plain", IP: "192.168.1.1"}, false, riskLeak},
		{"lan resolver under a tunnel", DNSLeakEntry{Kind: "plain", IP: "192.168.1.1"}, true, riskWarn},
		{"public plain resolver", DNSLeakEntry{Kind: "plain", IP: "223.5.5.5"}, false, riskWarn},
		{"doh", DNSLeakEntry{Kind: "doh"}, false, riskOK},
		{"dot", DNSLeakEntry{Kind: "dot"}, false, riskOK},
		{"doq is not measured yet", DNSLeakEntry{Kind: "doq"}, false, riskWarn},
	}
	for _, c := range cases {
		e := c.in
		assessDNS(&e, c.tun, "")
		if e.Risk != c.want {
			t.Errorf("%s: risk = %s, want %s (note %q)", c.name, e.Risk, c.want, e.Note)
		}
		if e.Note == "" {
			t.Errorf("%s: every verdict has to explain itself", c.name)
		}
	}
}

func TestAssessDNSNotesTheUnmeasuredRows(t *testing.T) {
	e := DNSLeakEntry{Kind: "doq", Note: "未实测（quic）"}
	assessDNS(&e, false, "")
	if e.Note[:len("未实测")] != "未实测" {
		t.Fatalf("the measured/not-measured note was dropped: %q", e.Note)
	}
}

func TestAssessDNSPromotesASharedExitAddress(t *testing.T) {
	e := DNSLeakEntry{Kind: "doh", IP: "203.0.113.7"}
	assessDNS(&e, false, "203.0.113.7")
	if e.Risk != riskWarn {
		t.Fatalf("a resolver sitting on the exit address is worth a warning, got %s", e.Risk)
	}
	if !e.SameAsExit {
		t.Fatal("SameAsExit was not set")
	}
}

func TestCleanResolverListTrimsAndDeduplicates(t *testing.T) {
	got := cleanResolverList([]string{" 1.1.1.1 ", "1.1.1.1", "", "8.8.8.8"})
	if len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "8.8.8.8" {
		t.Fatalf("cleanResolverList = %v", got)
	}
}

func TestOwnedByMatchesTheOwnerNotAFixedASN(t *testing.T) {
	google := geoInfo{ASN: "AS15169", Org: "Google LLC"}
	if !ownedBy(google, []string{"google"}) {
		t.Fatal("Google LLC is owned by google")
	}
	facebook := geoInfo{ASN: "AS32934", Org: "Facebook, Inc."}
	if ownedBy(facebook, []string{"google"}) {
		t.Fatal("a Facebook address is not a Google answer")
	}
	// An unknown owner must not be treated as a match: the whole point of the
	// check is to catch an answer that belongs to somebody unexpected.
	if ownedBy(geoInfo{}, []string{"google"}) {
		t.Fatal("an empty owner matched")
	}
}

func TestAssessDNSNamesTheOwnerOfAHijackedAnswer(t *testing.T) {
	e := DNSLeakEntry{
		Kind:      "plain",
		IP:        "1.1.1.1",
		Poisoned:  true,
		Canary:    "www.google.com",
		HijackIP:  "185.45.5.35",
		HijackASN: "AS44580",
		HijackOrg: "PQ HOSTING PLUS S.R.L.",
	}
	assessDNS(&e, false, "")
	if e.Risk != riskLeak {
		t.Fatalf("risk = %s, want %s", e.Risk, riskLeak)
	}
	for _, want := range []string{"185.45.5.35", "AS44580", "PQ HOSTING"} {
		if !strings.Contains(e.Note, want) {
			t.Errorf("the note has to name %q, got %q", want, e.Note)
		}
	}
}

func TestIsPrivateAddr(t *testing.T) {
	private := []string{"192.168.1.1", "10.0.0.1", "172.16.5.4", "127.0.0.1", "fe80::1", "fd00::1"}
	for _, ip := range private {
		if !isPrivateAddr(ip) {
			t.Errorf("%s should count as private", ip)
		}
	}
	for _, ip := range []string{"223.5.5.5", "1.1.1.1", "2606:4700:4700::1111", "", "dns.google"} {
		if isPrivateAddr(ip) {
			t.Errorf("%s should not count as private", ip)
		}
	}
}
