package main

import (
	"fmt"
	"os"

	"github.com/rangaroo/pcap-traffic-generator/internal/mutate"
	"gopkg.in/yaml.v3"
)

// yamlConfig mirrors the YAML file structure.
type yamlConfig struct {
	Mutate struct {
		SrcIP   string `yaml:"src_ip"`
		DstIP   string `yaml:"dst_ip"`
		SrcPort struct {
			Mode string `yaml:"mode"`
			Min  uint16 `yaml:"min"`
			Max  uint16 `yaml:"max"`
		} `yaml:"src_port"`
		DstPort struct {
			Mode string `yaml:"mode"`
			Min  uint16 `yaml:"min"`
			Max  uint16 `yaml:"max"`
		} `yaml:"dst_port"`
		Seed int64 `yaml:"seed"`
	} `yaml:"mutate"`
}

// replayFlags holds all CLI flag values for the replay subcommand.
type replayFlags struct {
	pcap          string
	iface         string
	configFile    string
	mode          string
	repeat        int
	remutate      bool
	mutateSrcIP   string
	mutateDstIP   string
	mutateSrcPort string
	mutateDstPort string
	seed          int64
}

// buildPolicy merges YAML config (if any) with CLI flag overrides.
// CLI flags win over YAML when non-zero/non-empty.
func buildPolicy(f replayFlags) (mutate.Policy, error) {
	var cfg yamlConfig

	if f.configFile != "" {
		data, err := os.ReadFile(f.configFile)
		if err != nil {
			return mutate.Policy{}, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return mutate.Policy{}, fmt.Errorf("parse config: %w", err)
		}
	}

	// CLI flags override YAML
	srcIPMode, srcIPCIDR := splitMode(f.mutateSrcIP, cfg.Mutate.SrcIP)
	dstIPMode, dstIPCIDR := splitMode(f.mutateDstIP, cfg.Mutate.DstIP)

	srcIP, err := mutate.ParseIPPolicy(srcIPMode, srcIPCIDR)
	if err != nil {
		return mutate.Policy{}, fmt.Errorf("src_ip: %w", err)
	}
	dstIP, err := mutate.ParseIPPolicy(dstIPMode, dstIPCIDR)
	if err != nil {
		return mutate.Policy{}, fmt.Errorf("dst_ip: %w", err)
	}

	srcPortMode, srcPortMin, srcPortMax := splitPortFlag(f.mutateSrcPort, cfg.Mutate.SrcPort.Mode, cfg.Mutate.SrcPort.Min, cfg.Mutate.SrcPort.Max)
	dstPortMode, dstPortMin, dstPortMax := splitPortFlag(f.mutateDstPort, cfg.Mutate.DstPort.Mode, cfg.Mutate.DstPort.Min, cfg.Mutate.DstPort.Max)

	srcPort, err := mutate.ParsePortPolicy(srcPortMode, srcPortMin, srcPortMax)
	if err != nil {
		return mutate.Policy{}, fmt.Errorf("src_port: %w", err)
	}
	dstPort, err := mutate.ParsePortPolicy(dstPortMode, dstPortMin, dstPortMax)
	if err != nil {
		return mutate.Policy{}, fmt.Errorf("dst_port: %w", err)
	}

	seed := f.seed
	if seed == 0 {
		seed = cfg.Mutate.Seed
	}

	return mutate.Policy{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
		Seed:    seed,
	}, nil
}

// splitMode parses "--mutate-src-ip 10.0.0.0/8" as mode=range,cidr=10.0.0.0/8.
// Falls back to yamlVal when cliVal is empty.
func splitMode(cliVal, yamlVal string) (mode, cidr string) {
	v := cliVal
	if v == "" {
		v = yamlVal
	}
	if v == "" || v == "keep" {
		return "keep", ""
	}
	// treat any non-"keep" string as a CIDR -> mode=range
	return "range", v
}

// splitPortFlag parses "--mutate-src-port 30000-60000".
func splitPortFlag(cliVal, yamlMode string, yamlMin, yamlMax uint16) (mode string, min, max uint16) {
	if cliVal == "" {
		return yamlMode, yamlMin, yamlMax
	}
	var lo, hi uint16
	if n, _ := fmt.Sscanf(cliVal, "%d-%d", &lo, &hi); n == 2 {
		return "range", lo, hi
	}
	return "keep", 0, 0
}
