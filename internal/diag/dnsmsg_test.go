package diag

import (
	"encoding/hex"
	"testing"
)

// buildReply assembles a response by hand so the parser is checked against
// bytes rather than against its own encoder.
func buildReply(t *testing.T, question string, answers [][]byte) []byte {
	t.Helper()
	qname, err := encodeQName(question)
	if err != nil {
		t.Fatalf("encodeQName: %v", err)
	}
	out := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, byte(len(answers)), 0x00, 0x00, 0x00, 0x00}
	out = append(out, qname...)
	out = append(out, 0x00, 0x01, 0x00, 0x01)
	for _, a := range answers {
		out = append(out, a...)
	}
	return out
}

// answerA builds an A record that points its name at the question with a
// compression pointer, which is what every real resolver sends.
func answerA(ip [4]byte, ttl uint32) []byte {
	out := []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01}
	out = append(out, byte(ttl>>24), byte(ttl>>16), byte(ttl>>8), byte(ttl))
	out = append(out, 0x00, 0x04)
	return append(out, ip[0], ip[1], ip[2], ip[3])
}

func TestDNSQueryMessageRoundTripsThroughTheParser(t *testing.T) {
	msg, err := dnsQueryMessage("www.google.com", "A", 0xbeef)
	if err != nil {
		t.Fatalf("dnsQueryMessage: %v", err)
	}
	if len(msg) < 12 {
		t.Fatalf("message is only %d bytes", len(msg))
	}
	name, next, err := decodeQName(msg, 12)
	if err != nil {
		t.Fatalf("decodeQName: %v", err)
	}
	if name != "www.google.com" {
		t.Fatalf("name = %q", name)
	}
	if msg[next] != 0x00 || msg[next+1] != 0x01 {
		t.Fatalf("question type = %x %x, want 0x0001", msg[next], msg[next+1])
	}
}

func TestParseDNSReplyReadsACompressedAnswer(t *testing.T) {
	raw := buildReply(t, "www.google.com", [][]byte{answerA([4]byte{93, 184, 216, 34}, 300)})
	rep, err := parseDNSReply(raw)
	if err != nil {
		t.Fatalf("parseDNSReply: %v", err)
	}
	if rep.RCode != 0 || rep.Truncated {
		t.Fatalf("flags decoded as rcode=%d truncated=%v", rep.RCode, rep.Truncated)
	}
	if len(rep.Answers) != 1 {
		t.Fatalf("answers = %d, want 1", len(rep.Answers))
	}
	got := rep.Answers[0]
	if got.Type != dnsTypeA || got.Data != "93.184.216.34" || got.TTL != 300 {
		t.Fatalf("answer = %+v", got)
	}
	if got.Name != "www.google.com" {
		t.Fatalf("compressed name decoded as %q", got.Name)
	}
}

func TestParseDNSReplyReportsResponseCodes(t *testing.T) {
	raw := buildReply(t, "blocked.example", nil)
	raw[3] = 0x83 // NXDOMAIN
	rep, err := parseDNSReply(raw)
	if err != nil {
		t.Fatalf("parseDNSReply: %v", err)
	}
	if rep.RCode != 3 || dnsRCodeName(rep.RCode) != "NXDOMAIN" {
		t.Fatalf("rcode = %d (%s)", rep.RCode, dnsRCodeName(rep.RCode))
	}
	if _, err := decodeDNSAnswers(raw, "A"); err == nil {
		t.Fatal("a non-zero rcode has to come back as an error")
	}
}

func TestDecodeDNSAnswersFlagsNothingButReturnsTheAddress(t *testing.T) {
	raw := buildReply(t, "www.google.com", [][]byte{answerA([4]byte{243, 185, 187, 39}, 60)})
	answers, err := decodeDNSAnswers(raw, "A")
	if err != nil {
		t.Fatalf("decodeDNSAnswers: %v", err)
	}
	if len(answers) != 1 || answers[0].Value != "243.185.187.39" {
		t.Fatalf("answers = %+v", answers)
	}
	if !poisonedAnswers[answers[0].Value] {
		t.Fatal("243.185.187.39 is a documented injected answer")
	}
}

func TestDecodeQNameFollowsCompression(t *testing.T) {
	// A message whose answer name is a pointer to offset 12, followed by a
	// second pointer into the middle of the first name.
	msg := []byte{0x00, 0x01, 0x00, 0x00}
	msg = append(msg, 0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00)
	// pointer to the "example" label, which starts at offset 8
	ptr := []byte{0xc0, 0x08}
	msg = append(msg, ptr...)
	name, next, err := decodeQName(msg, len(msg)-2)
	if err != nil {
		t.Fatalf("decodeQName: %v", err)
	}
	if name != "example" {
		t.Fatalf("name = %q, want example", name)
	}
	if next != len(msg) {
		t.Fatalf("next = %d, want %d", next, len(msg))
	}
}

func TestFormatIPv6CollapsesTheLongestZeroRun(t *testing.T) {
	cases := map[string]string{
		"20010db8000000000000000000000001": "2001:db8::1",
		"00000000000000000000000000000001": "::1",
		"00000000000000000000000000000000": "::",
		"20010db8000100020003000400050006": "2001:db8:1:2:3:4:5:6",
	}
	for in, want := range cases {
		raw, err := hex.DecodeString(in)
		if err != nil {
			t.Fatalf("bad fixture %q: %v", in, err)
		}
		if got := formatIPv6(raw); got != want {
			t.Errorf("formatIPv6(%s) = %q, want %q", in, got, want)
		}
	}
}
