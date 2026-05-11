package pcapio

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/rangaroo/pcap-traffic-generator/internal/flow"
)

const (
	ethHdrLen = 14
	ipMinHdr  = 20
)

// TimedPkt is one packet inside a session, with it original capture timestamp
// and the direction relative to the flow.Key
type TimedPkt struct {
	Timestamp time.Time
	Dir       flow.Dir
	Data      []byte // full raw frame (Ethernet + IP + L4 + payload)
}

// Session groups all packets belongin to one bidirectional flow.
type Session struct {
	Key     flow.Key
	Packets []TimedPkt
}

// Sessionize reads all packets from r and returns one Session per 5-tuple.
// Non-IPv4 packets and malformed frames are silently skipped (counted in Skipped)
func Sessionize(r *Reader) (sessions []Session, skipped int, err error) {
	index := make(map[flow.Key]*Session)

	for {
		pkt, rerr := r.Next()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, skipped, fmt.Errorf("read: %w", rerr)
		}

		key, dir, ok := classify(pkt.Data)
		if !ok {
			skipped++
			continue
		}

		s, exists := index[key]
		if !exists {
			s = &Session{Key: key}
			index[key] = s
		}
		s.Packets = append(s.Packets, TimedPkt{
			Timestamp: pkt.Timestamp,
			Dir:       dir,
			Data:      pkt.Data,
		})
	}

	sessions = make([]Session, 0, len(index))
	for _, s := range index {
		sessions = append(sessions, *s)
	}

	return sessions, skipped, nil
}

// classify parses a raw Ethernet frame and extracts the 5-tuple.
// Returns ok=false for non-IPv4 or malformed frames.
func classify(frame []byte) (flow.Key, flow.Dir, bool) {
	if len(frame) < ethHdrLen+ipMinHdr {
		return flow.Key{}, 0, false
	}

	ethertype := binary.BigEndian.Uint16(frame[12:14])
	if ethertype != 0x0800 { // not IPv4
		return flow.Key{}, 0, false
	}

	ip := frame[ethHdrLen:]
	if ip[0]>>4 != 4 { // not IPv4 version
		return flow.Key{}, 0, false
	}

	ipHdrLen := int(ip[0]&0x0f) * 4
	if len(ip) < ipHdrLen+4 { // need at least 4 bytes of L4 for ports
		return flow.Key{}, 0, false
	}

	proto := ip[9]
	if proto != 6 && proto != 17 { // only TCP and UDP
		log.Printf("pcapio: skipping proto %d", proto)
		return flow.Key{}, 0, false
	}

	srcIP := net.IP(ip[12:16])
	dstIP := net.IP(ip[16:20])

	l4 := ip[ipHdrLen:]
	srcPort := binary.BigEndian.Uint16(l4[0:2])
	dstPort := binary.BigEndian.Uint16(l4[2:4])

	key, dir := flow.Classify(srcIP, dstIP, srcPort, dstPort, proto)
	return key, dir, true
}
