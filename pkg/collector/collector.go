// Package collector loads eBPF and collects network connections
package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/gg-sentinel/ebpf-ai-sentinel/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target arm64 bpf ../../bpf/network.c -- -I../../bpf/headers

// rawEvent matches the C struct from our eBPF program
// Layout: timestamp(8) + pid(4) + dst_ip(4) + dst_port(2) + pad(2) + comm(16) = 36 bytes
type rawEvent struct {
	TimestampNs uint64
	PID         uint32
	DstIP       uint32
	DstPort     uint16
	Pad         uint16 // Exported so binary.Read can access it
	Comm        [16]byte
}

// Collector monitors network connections using eBPF
type Collector struct {
	objs    *bpfObjects
	link    link.Link
	reader  *perf.Reader
	eventCh chan types.Connection
	stopCh  chan struct{}
}

// New creates a new Collector
func New() (*Collector, error) {
	return &Collector{
		eventCh: make(chan types.Connection, 1000),
		stopCh:  make(chan struct{}),
	}, nil
}

// Start loads eBPF and begins monitoring
func (c *Collector) Start(ctx context.Context) error {
	// Allow eBPF to use memory
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %w", err)
	}

	// Load eBPF program
	c.objs = &bpfObjects{}
	if err := loadBpfObjects(c.objs, nil); err != nil {
		return fmt.Errorf("failed to load eBPF: %w", err)
	}

	// Attach to tcp_connect
	l, err := link.Kprobe("tcp_connect", c.objs.TraceConnect, nil)
	if err != nil {
		c.Close()
		return fmt.Errorf("failed to attach kprobe: %w", err)
	}
	c.link = l

	// Create perf reader for events
	reader, err := perf.NewReader(c.objs.Events, 4096)
	if err != nil {
		c.Close()
		return fmt.Errorf("failed to create reader: %w", err)
	}
	c.reader = reader

	// Start reading events
	go c.readEvents(ctx)

	return nil
}

// Events returns the channel of connections
func (c *Collector) Events() <-chan types.Connection {
	return c.eventCh
}

// readEvents reads from the perf buffer
func (c *Collector) readEvents(ctx context.Context) {
	defer close(c.eventCh)

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopCh:
			return
		default:
		}

		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			continue
		}

		if record.LostSamples > 0 {
			continue
		}

		conn, err := parseEvent(record.RawSample)
		if err != nil {
			continue
		}

		// Skip local connections (not internet)
		if types.IsPrivateIP(conn.DestIP) {
			continue
		}

		select {
		case c.eventCh <- conn:
		default:
			// Channel full, skip
		}
	}
}

// parseEvent converts raw bytes to a Connection
func parseEvent(data []byte) (types.Connection, error) {
	var raw rawEvent
	reader := bytes.NewReader(data)

	if err := binary.Read(reader, binary.LittleEndian, &raw); err != nil {
		return types.Connection{}, err
	}

	// Convert process name
	processName := string(bytes.TrimRight(raw.Comm[:], "\x00"))

	// Convert IP
	destIP := net.IPv4(
		byte(raw.DstIP),
		byte(raw.DstIP>>8),
		byte(raw.DstIP>>16),
		byte(raw.DstIP>>24),
	)

	return types.Connection{
		Timestamp:   time.Now(),
		ProcessName: processName,
		PID:         raw.PID,
		DestIP:      destIP,
		DestPort:    raw.DstPort,
		IsKnownApp:  types.IsKnownApp(processName),
	}, nil
}

// Close cleans up resources
func (c *Collector) Close() error {
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}

	if c.reader != nil {
		c.reader.Close()
	}

	if c.link != nil {
		c.link.Close()
	}

	if c.objs != nil {
		c.objs.Close()
	}

	return nil
}
