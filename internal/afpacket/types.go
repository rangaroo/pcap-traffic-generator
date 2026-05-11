package afpacket

const (
	tpacketV2 = 1 // TPACKET_V2 for TX ring

	tpStatusAvailable   = 0
	tpStatusSendRequest = 1
)

const (
	defaultTXFrameSize  = 2048
	defaultTXFrameCount = 256
	defaultTXBlockSize  = 4096
)

// TXConfig holds parameters for opening a TPACKET_V2 TX ring.
type TXConfig struct {
	Interface  string
	FrameSize  int
	FrameCount int
}

// TXFrameHeader mirrors tpacket2_hdr from <linux/if_packet.h>.
type TXFrameHeader struct {
	Status  uint32
	Len     uint32
	SnapLen uint32
	Mac     uint16
	Net     uint16
	Sec     uint32
	Nsec    uint32
	VlanTCI uint16
	VLANID  uint16
	_       [4]byte
}

// TXRing owns all state for a TPACKET_V2 transmit ring.
type TXRing struct {
	fd         int
	mmap       []byte
	frames     [][]byte
	frameSize  int
	frameCount int
	cur        int
}
