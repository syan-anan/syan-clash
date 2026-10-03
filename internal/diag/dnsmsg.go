package diag

import (
	"fmt"
	"strings"
)

// A minimal DNS wire codec, used only by the leak panel.
//
// That panel has to ask one exact resolver a question and read the answer
// itself: Go's resolver hides which server answered, retries on its own, and
// cannot be pointed at a DoT or DoH endpoint given by address. Speaking
// RFC 1035 directly is less code than working around all of that, and it is
// also what lets the panel see a poisoned answer as an answer instead of as a
// dial failure.

// DNS record types this codec understands. Anything else is reported by number.
const (
	dnsTypeA     = 1
	dnsTypeCNAME = 5
	dnsTypePTR   = 12
	dnsTypeTXT   = 16
	dnsTypeAAAA  = 28
	dnsClassIN   = 1
)

// dnsRecord is one answer.
type dnsRecord struct {
	Name string
	Type int
	TTL  uint32
	Data string
}

// dnsReply is the decoded response.
type dnsReply struct {
	ID         uint16
	RCode      int
	Truncated  bool
	RecursionA bool
	Answers    []dnsRecord
}

// dnsRCodeName turns a response code into the word the panel shows.
func dnsRCodeName(code int) string {
	switch code {
	case 0:
		return "NOERROR"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	}
	return "RCODE" + itoa(code)
}

// dnsTypeNumber maps a query type name onto its number.
func dnsTypeNumber(qtype string) (int, bool) {
	switch strings.ToUpper(strings.TrimSpace(qtype)) {
	case "", "A":
		return dnsTypeA, true
	case "AAAA":
		return dnsTypeAAAA, true
	case "CNAME":
		return dnsTypeCNAME, true
	case "PTR":
		return dnsTypePTR, true
	case "TXT":
		return dnsTypeTXT, true
	}
	return 0, false
}

// dnsQueryMessage builds a standard recursive query with one question.
func dnsQueryMessage(name, qtype string, id uint16) ([]byte, error) {
	qname, err := encodeQName(name)
	if err != nil {
		return nil, err
	}
	qt, ok := dnsTypeNumber(qtype)
	if !ok {
		return nil, fmt.Errorf("不支持的记录类型 %s", qtype)
	}
	buf := make([]byte, 0, len(qname)+16)
	buf = append(buf, byte(id>>8), byte(id))
	buf = append(buf, 0x01, 0x00) // standard query, recursion desired
	buf = append(buf, 0x00, 0x01) // qdcount = 1
	buf = append(buf, 0x00, 0x00) // ancount
	buf = append(buf, 0x00, 0x00) // nscount
	buf = append(buf, 0x00, 0x00) // arcount
	buf = append(buf, qname...)
	buf = append(buf, byte(qt>>8), byte(qt), 0x00, dnsClassIN)
	return buf, nil
}

// encodeQName turns a domain name into length-prefixed labels.
func encodeQName(name string) ([]byte, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return nil, fmt.Errorf("查询名不能为空")
	}
	out := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return nil, fmt.Errorf("域名 %q 里有空标签", name)
		}
		if len(label) > 63 {
			return nil, fmt.Errorf("域名 %q 的标签 %q 超过 63 字节", name, label)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	if len(out) > 255 {
		return nil, fmt.Errorf("域名 %q 编码后超过 255 字节", name)
	}
	return out, nil
}

// decodeQName reads a name at off, following compression pointers. It returns
// the name and the offset just past the name in the original stream.
func decodeQName(msg []byte, off int) (string, int, error) {
	var sb strings.Builder
	next := -1
	seen := 0
	for {
		if off >= len(msg) {
			return "", 0, fmt.Errorf("DNS 报文在域名处截断")
		}
		length := int(msg[off])
		if length == 0 {
			off++
			break
		}
		if length&0xc0 == 0xc0 {
			if off+1 >= len(msg) {
				return "", 0, fmt.Errorf("DNS 压缩指针截断")
			}
			ptr := int(msg[off]&0x3f)<<8 | int(msg[off+1])
			if next < 0 {
				next = off + 2
			}
			seen++
			if seen > 32 {
				return "", 0, fmt.Errorf("DNS 压缩指针成环")
			}
			off = ptr
			continue
		}
		if off+1+length > len(msg) {
			return "", 0, fmt.Errorf("DNS 标签截断")
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(msg[off+1 : off+1+length])
		off += 1 + length
	}
	if next < 0 {
		next = off
	}
	return sb.String(), next, nil
}

// parseDNSReply decodes a response message.
func parseDNSReply(msg []byte) (dnsReply, error) {
	var rep dnsReply
	if len(msg) < 12 {
		return rep, fmt.Errorf("DNS 响应只有 %d 字节", len(msg))
	}
	rep.ID = uint16(msg[0])<<8 | uint16(msg[1])
	flags := uint16(msg[2])<<8 | uint16(msg[3])
	rep.Truncated = flags&0x0200 != 0
	rep.RecursionA = flags&0x0080 != 0
	rep.RCode = int(flags & 0x000f)
	qd := int(msg[4])<<8 | int(msg[5])
	an := int(msg[6])<<8 | int(msg[7])

	off := 12
	for i := 0; i < qd; i++ {
		_, next, err := decodeQName(msg, off)
		if err != nil {
			return rep, err
		}
		if next+4 > len(msg) {
			return rep, fmt.Errorf("DNS 问题段截断")
		}
		off = next + 4
	}
	for i := 0; i < an; i++ {
		name, next, err := decodeQName(msg, off)
		if err != nil {
			return rep, err
		}
		if next+10 > len(msg) {
			return rep, fmt.Errorf("DNS 资源记录头截断")
		}
		rrType := int(msg[next])<<8 | int(msg[next+1])
		ttl := uint32(msg[next+4])<<24 | uint32(msg[next+5])<<16 | uint32(msg[next+6])<<8 | uint32(msg[next+7])
		rdLen := int(msg[next+8])<<8 | int(msg[next+9])
		rdata := next + 10
		if rdata+rdLen > len(msg) {
			return rep, fmt.Errorf("DNS 资源记录数据截断")
		}
		rec := dnsRecord{Name: name, Type: rrType, TTL: ttl}
		switch rrType {
		case dnsTypeA:
			if rdLen == 4 {
				rec.Data = itoa(int(msg[rdata])) + "." + itoa(int(msg[rdata+1])) + "." +
					itoa(int(msg[rdata+2])) + "." + itoa(int(msg[rdata+3]))
			}
		case dnsTypeAAAA:
			if rdLen == 16 {
				rec.Data = formatIPv6(msg[rdata : rdata+16])
			}
		case dnsTypeCNAME, dnsTypePTR:
			decoded, _, err := decodeQName(msg, rdata)
			if err != nil {
				return rep, err
			}
			rec.Data = decoded
		case dnsTypeTXT:
			var parts []string
			for p := rdata; p < rdata+rdLen; {
				l := int(msg[p])
				p++
				if p+l > rdata+rdLen {
					break
				}
				parts = append(parts, string(msg[p:p+l]))
				p += l
			}
			rec.Data = strings.Join(parts, "")
		}
		rep.Answers = append(rep.Answers, rec)
		off = rdata + rdLen
	}
	return rep, nil
}

// formatIPv6 renders 16 bytes in the compressed form the panel shows.
func formatIPv6(b []byte) string {
	var groups [8]uint16
	for i := 0; i < 8; i++ {
		groups[i] = uint16(b[i*2])<<8 | uint16(b[i*2+1])
	}
	// Find the longest run of zeros so it can be collapsed into "::".
	bestStart, bestLen := -1, 0
	for i := 0; i < 8; {
		if groups[i] != 0 {
			i++
			continue
		}
		j := i
		for j < 8 && groups[j] == 0 {
			j++
		}
		if j-i > bestLen {
			bestStart, bestLen = i, j-i
		}
		i = j
	}
	if bestLen < 2 {
		bestStart, bestLen = -1, 0
	}
	var sb strings.Builder
	for i := 0; i < 8; i++ {
		if i == bestStart {
			sb.WriteString("::")
			i += bestLen - 1
			continue
		}
		if i > 0 && !strings.HasSuffix(sb.String(), ":") {
			sb.WriteByte(':')
		}
		sb.WriteString(strings.ToLower(fmt.Sprintf("%x", groups[i])))
	}
	return sb.String()
}
