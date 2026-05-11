package mutate

import (
	"fmt"
	"net"
)

type FieldMode uint8

const (
	ModeKeep FieldMode = iota
	ModeRange
)

type IPPolicy struct {
	Mode FieldMode
	CIDR *net.IPNet
}

type PortPolicy struct {
	Mode FieldMode
	Min  uint16
	Max  uint16
}

type Policy struct {
	SrcIP   IPPolicy
	DstIP   IPPolicy
	SrcPort PortPolicy
	DstPort PortPolicy
	Seed    int64
}

func ParseIPPolicy(mode, cidr string) (IPPolicy, error) {
	switch mode {
	case "keep", "":
		return IPPolicy{Mode: ModeKeep}, nil
	case "range":
		if cidr == "" {
			return IPPolicy{}, fmt.Errorf("mode=range requires cidr")
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return IPPolicy{}, fmt.Errorf("invalid cidr %q: %w", cidr, err)
		}
		if network.IP.To4() == nil {
			return IPPolicy{}, fmt.Errorf("only IPv4 CIDRs supported")
		}
		return IPPolicy{Mode: ModeRange, CIDR: network}, nil
	default:
		return IPPolicy{}, fmt.Errorf("unknown mode %q (want keep|range)", mode)
	}
}

func ParsePortPolicy(mode string, min, max uint16) (PortPolicy, error) {
	switch mode {
	case "keep", "":
		return PortPolicy{Mode: ModeKeep}, nil
	case "range":
		if min > max {
			return PortPolicy{}, fmt.Errorf("port min %d > max %d", min, max)
		}
		return PortPolicy{Mode: ModeRange, Min: min, Max: max}, nil
	default:
		return PortPolicy{}, fmt.Errorf("unknown mode %q (want keep|range)", mode)
	}
}
