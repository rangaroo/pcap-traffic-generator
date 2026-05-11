package replay

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/rangaroo/pcap-traffic-generator/internal/afpacket"
	"github.com/rangaroo/pcap-traffic-generator/internal/mutate"
	"github.com/rangaroo/pcap-traffic-generator/internal/pcapio"
)

// Mode selects the replay timing strategy.
type Mode uint8

const (
	ModeBurst Mode = iota // ignore pcap timestamps, send as fast as possible
	ModeTimed             // preserve inter-packet delays from the pcap
)

// Stats holds running counters for a replay run.
type Stats struct {
	Sent     uint64
	Errors   uint64
	Sessions uint64
}

// Config controls a single replay run.
type Config struct {
	Iface    string
	Mode     Mode
	Repeat   int  // 0 = run once; N > 0 = total N passes
	Remutate bool // re-randomize mutation each repeat iteration
}

func runBurst(
	ctx context.Context,
	tx *afpacket.TXRing,
	sessions []pcapio.Session,
	rw *mutate.Rewriter,
	stats *Stats,
) error {
	for i := range sessions {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		for j := range sessions[i].Packets {
			pkt := &sessions[i].Packets[j]
			frame := cloneFrame(pkt.Data)
			if err := rw.Rewrite(frame, sessions[i].Key, pkt.Dir); err != nil {
				stats.Errors++
				continue
			}
			if err := tx.Send(frame); err != nil {
				stats.Errors++
				continue
			}
			stats.Sent++
		}
	}

	return nil
}

type timedPkt struct {
	sessionIdx int
	pktIdx     int
	ts         time.Time
}

func runTimed(
	ctx context.Context,
	tx *afpacket.TXRing,
	sessions []pcapio.Session,
	rw *mutate.Rewriter,
	stats *Stats,
) error {
	total := 0
	for i := range sessions {
		total += len(sessions[i].Packets)
	}

	all := make([]timedPkt, 0, total)
	for i := range sessions {
		for j := range sessions[i].Packets {
			all = append(all, timedPkt{
				sessionIdx: i,
				pktIdx:     j,
				ts:         sessions[i].Packets[j].Timestamp,
			})
		}
	}

	sort.Slice(all, func(i, j int) bool { return all[i].ts.Before(all[j].ts) })

	if len(all) == 0 {
		return nil
	}

	origin := all[0].ts
	start := time.Now()

	for _, e := range all {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		sleepUntil(start.Add(e.ts.Sub(origin)))

		pkt := &sessions[e.sessionIdx].Packets[e.pktIdx]
		frame := cloneFrame(pkt.Data)
		if err := rw.Rewrite(frame, sessions[e.sessionIdx].Key, pkt.Dir); err != nil {
			stats.Errors++
			continue
		}
		if err := tx.Send(frame); err != nil {
			stats.Errors++
			continue
		}
		stats.Sent++
	}

	return nil
}

// sleepUntil sleeps then waits the final 200 microseconds for sub ms accuracy.
func sleepUntil(target time.Time) {
	const busyThreshold = 200 * time.Microsecond
	if d := time.Until(target); d > busyThreshold {
		time.Sleep(d - busyThreshold)
	}
	for time.Now().Before(target) {
	}
}

func cloneFrame(src []byte) []byte {
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

// Run opens a TX ring on cfg.Iface and replays sessions.
func Run(ctx context.Context, sessions []pcapio.Session, rw *mutate.Rewriter, cfg Config) (Stats, error) {
	tx, err := afpacket.OpenTX(afpacket.TXConfig{Interface: cfg.Iface})
	if err != nil {
		return Stats{}, fmt.Errorf("open tx: %w", err)
	}
	defer tx.Close()

	passes := cfg.Repeat
	if passes <= 0 {
		passes = 1
	}

	var stats Stats
	stats.Sessions = uint64(len(sessions))

	for pass := 0; pass < passes; pass++ {
		if ctx.Err() != nil {
			break
		}

		if cfg.Mode == ModeTimed {
			err = runTimed(ctx, tx, sessions, rw, &stats)
		} else {
			err = runBurst(ctx, tx, sessions, rw, &stats)
		}
		if err != nil {
			return stats, err
		}

		if cfg.Remutate && pass < passes-1 {
			rw = mutate.NewRewriter(rw.Policy())
		}
	}
	return stats, nil
}
