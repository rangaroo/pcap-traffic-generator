package pcapio

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// RawPacket is a single frame as read from the pcap file.
type RawPacket struct {
	Data      []byte
	Timestamp time.Time
}

// Reader wraps a pcapgo file reader and validates link type.
type Reader struct {
	f *os.File
	r *pcapgo.Reader
}

// Open opens a pcap file for reading.
// Returns an error if the link type is not Ethernet.
func Open(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	r, err := pcapgo.NewReader(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("pcap open: %w", err)
	}

	if r.LinkType() != layers.LinkTypeEthernet {
		f.Close()
		return nil, fmt.Errorf("unsupported link type %v (want Ethernet)", r.LinkType())
	}

	return &Reader{f: f, r: r}, nil
}

// Close releases the underlying file.
func (rd *Reader) Close() error { return rd.f.Close() }

// Next reads the next packet from the pcap.
// Returns io.EOF when the file is exhausted.
func (rd *Reader) Next() (RawPacket, error) {
	data, ci, err := rd.r.ReadPacketData()
	if err != nil {
		if err == io.EOF {
			return RawPacket{}, io.EOF
		}
		return RawPacket{}, err
	}

	// make a private copy, pcapgo may reuse the buffer
	buf := make([]byte, len(data))
	copy(buf, data)

	return RawPacket{Data: buf, Timestamp: ci.Timestamp}, nil
}
