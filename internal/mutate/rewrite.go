package mutate

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"

	"github.com/rangaroo/pcap-traffic-generator/internal/flow"
)

const (
	ethHdrLen = 14
	ipMinHdr  = 20
)

// Mapping holds the assigned (new) addresses for one canonical flow.Key.
type Mapping struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
}

// Rewriter assigns and caches one Mapping per flow.Key, then rewrites frames.
type Rewriter struct {
	mu       sync.Mutex
	policy   Policy
	mappings map[flow.Key]Mapping
}

func NewRewriter(p Policy) *Rewriter {
	return &Rewriter{policy: p, mappings: make(map[flow.Key]Mapping)}
}

// Rewrite patches the IP and L4 headers of frame in-place.
// key is the canonical flow key; dir is the packet's direction.
// Returns error if frame is too short or has unsupported proto.
func (rw *Rewriter) Rewrite(frame []byte, key flow.Key, dir flow.Dir) error {
	if len(frame) < ethHdrLen+ipMinHdr {
		return fmt.Errorf("frame too short (%d bytes)", len(frame))
	}

	ip := frame[ethHdrLen:]
	ipHdrLen := int(ip[0]&0x0f) * 4
	if len(ip) < ipHdrLen+4 {
		return fmt.Errorf("ip header truncated")
	}

	proto := ip[9]
	if proto != 6 && proto != 17 {
		return fmt.Errorf("unsupported proto %d", proto)
	}

	m := rw.getMapping(key)

	// Determine which addresses/ports to apply based on packet direction.
	// Forward: Src to Dst.
	// Reverse: Dst to Src.

	var (
		newSrcIP   [4]byte
		newDstIP   [4]byte
		newSrcPort uint16
		newDstPort uint16
	)
	if dir == flow.DirForward {
		newSrcIP, newDstIP = m.SrcIP, m.DstIP
		newSrcPort, newDstPort = m.SrcPort, m.DstPort
	} else {
		newSrcIP, newDstIP = m.DstIP, m.SrcIP
		newSrcPort, newDstPort = m.DstPort, m.SrcPort
	}

	oldSrcIP := [4]byte(ip[12:16])
	oldDstIP := [4]byte(ip[16:20])
	oldSrcPort := binary.BigEndian.Uint16(ip[ipHdrLen : ipHdrLen+2])
	oldDstPort := binary.BigEndian.Uint16(ip[ipHdrLen+2 : ipHdrLen+4])

	// Patch IP header fields.
	copy(ip[12:16], newSrcIP[:])
	copy(ip[16:20], newDstIP[:])

	// Recompute IP checksum incrementally (RFC 1624).
	ipCsumOff := 10
	csum := ^binary.BigEndian.Uint16(ip[ipCsumOff : ipCsumOff+2])
	csum = rfc1624Update(csum, binary.BigEndian.Uint16(oldSrcIP[0:2]), binary.BigEndian.Uint16(newSrcIP[0:2]))
	csum = rfc1624Update(csum, binary.BigEndian.Uint16(oldSrcIP[2:4]), binary.BigEndian.Uint16(newSrcIP[2:4]))
	csum = rfc1624Update(csum, binary.BigEndian.Uint16(oldDstIP[0:2]), binary.BigEndian.Uint16(newDstIP[0:2]))
	csum = rfc1624Update(csum, binary.BigEndian.Uint16(oldDstIP[2:4]), binary.BigEndian.Uint16(newDstIP[2:4]))
	binary.BigEndian.PutUint16(ip[ipCsumOff:ipCsumOff+2], ^csum)

	// Patch L4 ports.
	l4 := ip[ipHdrLen:]
	binary.BigEndian.PutUint16(l4[0:2], newSrcPort)
	binary.BigEndian.PutUint16(l4[2:4], newDstPort)

	// Recompute L4 checksum incrementally.
	var l4CsumOff int
	switch proto {
	case 6: // TCP
		l4CsumOff = 16
	case 17: // UDP
		l4CsumOff = 6
	}
	if len(l4) >= l4CsumOff+2 {
		l4csum := ^binary.BigEndian.Uint16(l4[l4CsumOff : l4CsumOff+2])
		l4csum = rfc1624Update(l4csum, binary.BigEndian.Uint16(oldSrcIP[0:2]), binary.BigEndian.Uint16(newSrcIP[0:2]))
		l4csum = rfc1624Update(l4csum, binary.BigEndian.Uint16(oldSrcIP[2:4]), binary.BigEndian.Uint16(newSrcIP[2:4]))
		l4csum = rfc1624Update(l4csum, binary.BigEndian.Uint16(oldDstIP[0:2]), binary.BigEndian.Uint16(newDstIP[0:2]))
		l4csum = rfc1624Update(l4csum, binary.BigEndian.Uint16(oldDstIP[2:4]), binary.BigEndian.Uint16(newDstIP[2:4]))
		l4csum = rfc1624Update(l4csum, oldSrcPort, newSrcPort)
		l4csum = rfc1624Update(l4csum, oldDstPort, newDstPort)
		binary.BigEndian.PutUint16(l4[l4CsumOff:l4CsumOff+2], ^l4csum)
	}

	return nil
}

func (rw *Rewriter) getMapping(key flow.Key) Mapping {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if m, ok := rw.mappings[key]; ok {
		return m
	}

	m := rw.assignMapping(key)
	rw.mappings[key] = m
	return m
}

func (rw *Rewriter) assignMapping(key flow.Key) Mapping {
	// Seed RNG per-session: same key -> same tuple every run
	r := rand.New(rand.NewSource(int64(key.Hash()) ^ rw.policy.Seed))

	m := Mapping{
		SrcIP:   key.SrcIP,
		DstIP:   key.DstIP,
		SrcPort: key.SrcPort,
		DstPort: key.DstPort,
	}

	if rw.policy.SrcIP.Mode == ModeRange {
		m.SrcIP = randIPInNet(r, rw.policy.SrcIP.CIDR)
	}
	if rw.policy.DstIP.Mode == ModeRange {
		m.SrcIP = randIPInNet(r, rw.policy.DstIP.CIDR)
	}
	if rw.policy.SrcPort.Mode == ModeRange {
		p := rw.policy.SrcPort
		m.SrcPort = p.Min + uint16(r.Intn(int(p.Max-p.Min+1)))
	}
	if rw.policy.DstPort.Mode == ModeRange {
		p := rw.policy.DstPort
		m.DstPort = p.Min + uint16(r.Intn(int(p.Max-p.Min+1)))
	}

	return m
}

// randIPInNet picks a random host address within network.
func randIPInNet(r *rand.Rand, network *net.IPNet) [4]byte {
	ip4 := network.IP.To4()
	mask := network.Mask

	// count host bits
	ones, bits := network.Mask.Size()
	hostBits := bits - ones

	base := binary.BigEndian.Uint32(ip4)
	hostRange := uint32(1)<<hostBits - 2 // exclude network and broadcast
	if hostRange == 0 {
		hostRange = 1
	}
	host := uint32(r.Int63n(int64(hostRange))) + 1

	ipInt := (base & binary.BigEndian.Uint32(mask)) | host
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], ipInt)
	return out
}

// rfc1624Update applies one incremental checksum update step.
// new_csum = ~(~csum + ~old + new) using 16-bit ones-complement arithmetic.
func rfc1624Update(csum, oldVal, newVal uint16) uint16 {
	s := uint32(csum) + uint32(^oldVal) + uint32(newVal)
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return uint16(s)
}
