package bpf

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PacketHandler is called for each captured packet
type PacketHandler func(packet gopacket.Packet, captureInfo gopacket.CaptureInfo)

// Capturer manages BPF packet capture
type Capturer struct {
	handle        *pcap.Handle
	bufferPool    *sync.Pool
	packetsChan   chan gopacket.Packet
	metrics       *CaptureMetrics
	interfaceName string
	port          int
}

// CaptureMetrics tracks performance statistics
type CaptureMetrics struct {
	PacketsReceived int64
	BytesReceived   int64
	DroppedPackets  int64
	// Add more metrics as needed
}

// NewCapturer creates a new BPF packet capturer
func NewCapturer(interfaceName string, port int) (*Capturer, error) {
	handle, err := pcap.OpenLive(interfaceName, 65535, true, 1*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("failed to open device: %w", err)
	}

	filter := fmt.Sprintf("udp and port %d", port)
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("BPF filter failed: %w", err)
	}

	bufferPool := &sync.Pool{
		New: func() interface{} {
			// Pre-allocate buffers of appropriate size
			return make([]byte, 65535)
		},
	}

	return &Capturer{
		interfaceName: interfaceName,
		port:          port,
		handle:        handle,
		bufferPool:    bufferPool,
		packetsChan:   make(chan gopacket.Packet, 1000),
		metrics:       &CaptureMetrics{},
	}, nil
}

// Start begins capturing packets and processing them with the provided handler
func (c *Capturer) Start(ctx context.Context, handler PacketHandler) error {
	log.Printf("Starting capture on %s with filter: udp and port %d", c.interfaceName, c.port)

	go func() {
		defer c.handle.Close()

		for {
			select {
			case <-ctx.Done():
				return
			default:
				data, captureInfo, err := c.handle.ZeroCopyReadPacketData()
				if err == pcap.NextErrorTimeoutExpired {
					continue
				} else if err != nil {
					log.Printf("Error reading packet: %v", err)
					continue
				}

				// Create a copy of the data since it will be overwritten by the next ZeroCopyReadPacketData call
				buffer := c.bufferPool.Get().([]byte)
				copy(buffer[:len(data)], data)

				packet := gopacket.NewPacket(buffer[:len(data)], layers.LayerTypeEthernet, gopacket.Default)
				packet.Metadata().CaptureInfo = captureInfo

				// Track metrics
				c.metrics.PacketsReceived++
				c.metrics.BytesReceived += int64(len(data))

				// Process the packet
				go func() {
					handler(packet, captureInfo)
					// Return buffer to pool after processing
					c.bufferPool.Put(buffer)
				}()
			}
		}
	}()

	return nil
}

// Stop stops the packet capture
func (c *Capturer) Stop() {
	if c.handle != nil {
		c.handle.Close()
		c.handle = nil
	}
}

// GetMetrics returns the current capture metrics
func (c *Capturer) GetMetrics() *CaptureMetrics {
	return c.metrics
}
