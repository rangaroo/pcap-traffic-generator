package flow

import (
	"encoding/binary"
	"hash/fnv"
	"net"
)

// Dir is the direction of a packet relative to Key.
type Dir uint8

const (
	DirForward Dir = iota // packet goes Src -> Dst
	DirReverse            // packet goes Dst -> Src
)

// Key is a 5-tuple of a session
// The "smaller" endpoint is always in Src* so that A->B and B->A share a key.
type Key struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

// Classify returns the Key and a direction of a packet
// described by the given raw (src, dst) 5-tuple.
func Classify(srcIP, dstIP net.IP, srcPort, dstPort uint16, proto uint8) (Key, Dir) {
	var s, d [4]byte
	copy(s[:], srcIP.To4())
	copy(d[:], dstIP.To4())

	// order: smaller (IP, port) pair goes to Src
	fwd := less(s, srcPort, d, dstPort)
	if fwd {
		return Key{
			SrcIP:   s,
			DstIP:   d,
			SrcPort: srcPort,
			DstPort: dstPort,
			Proto:   proto,
		}, DirForward
	}
	return Key{
		SrcIP:   d,
		DstIP:   s,
		SrcPort: dstPort,
		DstPort: srcPort,
		Proto:   proto,
	}, DirReverse
}

// Hash returns a 64-bit hash of the key, used to seed deterministic mutation.
func (k Key) Hash() uint64 {
	h := fnv.New64a()
	h.Write(k.SrcIP[:])
	h.Write(k.DstIP[:])

	var ports [4]byte
	binary.LittleEndian.PutUint16(ports[0:], k.SrcPort)
	binary.LittleEndian.PutUint16(ports[2:], k.DstPort)

	h.Write(ports[:])
	h.Write([]byte{k.Proto})

	return h.Sum64()
}

func less(aIP [4]byte, aPort uint16, bIP [4]byte, bPort uint16) bool {
	for i := range aIP {
		if aIP[i] != bIP[i] {
			return aIP[i] < bIP[i]
		}
	}
	return aPort <= bPort
}
