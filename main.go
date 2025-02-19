package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	udpPort    = 54321
	packetRate = 100000 // 100,000 packets/sec

)

func main() {
	defaultDevice := "lo0"

	// Benchmark PCAP/BPF
	fmt.Println("Running pcap/BPF benchmark...")
	donePCAP := make(chan bool)
	go generateUDPTraffic(donePCAP, "127.0.0.1")
	time.Sleep(100 * time.Millisecond) // Let traffic start
	benchmarkPcap(defaultDevice)
	donePCAP <- true

	// Benchmark Socket
	fmt.Println("\nRunning standard socket benchmark...")
	doneSocket := make(chan bool)
	go generateUDPTraffic(doneSocket, "127.0.0.1")
	time.Sleep(100 * time.Millisecond)
	benchmarkStandardSocket()
	doneSocket <- true
}

func generateUDPTraffic(done chan bool, targetIP string) {
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP(targetIP),
		Port: udpPort,
	})
	if err != nil {
		log.Printf("UDP sender failed: %v", err)
		return
	}
	defer conn.Close()

	data := []byte("test")
	ticker := time.NewTicker(time.Second / time.Duration(packetRate))
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			conn.Write(data)
		}
	}
}

func benchmarkPcap(device string) {
	handle, err := pcap.OpenLive(device, 65535, true, time.Millisecond*100)
	if err != nil {
		log.Fatalf("Failed to open device: %v", err)
	}
	defer handle.Close()

	// Verify BPF filter
	if err := handle.SetBPFFilter(fmt.Sprintf("udp and port %d", udpPort)); err != nil {
		log.Fatalf("BPF filter failed: %v", err)
	}

	log.Println("PCAP capture started...") // Debug log

	var (
		packets    int
		totalBytes int
		times      []time.Duration
		start      = time.Now()
		deadline   = start.Add(5 * time.Second) // 5-second benchmark
	)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	for {
		if time.Now().After(deadline) {
			break
		}

		select {
		case packet := <-packetChan:
			if packet == nil {
				continue
			}

			processStart := time.Now()
			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				packets++
				totalBytes += len(packet.Data())
				times = append(times, time.Since(processStart))
			}

		case <-time.After(100 * time.Millisecond):
			continue
		}
	}

	printStats("PCAP/BPF", packets, totalBytes, times, time.Since(start))
}

func benchmarkStandardSocket() {
	// Bind to UDP port directly
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: udpPort})
	if err != nil {
		log.Fatalf("Failed to create UDP socket: %v", err)
	}
	defer conn.Close()

	var (
		packets    int
		totalBytes int
		times      []time.Duration
		start      = time.Now()
		deadline   = start.Add(5 * time.Second) // 5-second benchmark
		buf        = make([]byte, 65535)
	)

	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		processStart := time.Now()

		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}

		packets++
		totalBytes += n
		times = append(times, time.Since(processStart))
	}

	printStats("Standard Socket", packets, totalBytes, times, time.Since(start))
}

// printStats and sortDurations functions remain unchanged

func printStats(name string, packets, bytes int, times []time.Duration, duration time.Duration) {
	if len(times) == 0 {
		fmt.Printf("--- %s Results ---\nNo packets captured\n", name)
		return
	}

	sortDurations(times)

	var totalLatency time.Duration
	for _, t := range times {
		totalLatency += t
	}

	avgLatency := totalLatency / time.Duration(len(times))

	fmt.Printf("--- %s Results ---\n", name)
	fmt.Printf("Test duration: %.2f seconds\n", duration.Seconds())
	fmt.Printf("Packets captured: %d\n", packets)
	fmt.Printf("Throughput: %.2f packets/sec\n", float64(packets)/duration.Seconds())
	fmt.Printf("Data rate: %.2f MB/sec\n", float64(bytes)/(1024*1024)/duration.Seconds())
	fmt.Printf("Average latency: %v\n", avgLatency)
	fmt.Printf("Min latency: %v\n", times[0])
	fmt.Printf("P50 latency: %v\n", times[len(times)*50/100])
	fmt.Printf("P95 latency: %v\n", times[len(times)*95/100])
	fmt.Printf("P99 latency: %v\n", times[len(times)*99/100])
	fmt.Printf("Max latency: %v\n", times[len(times)-1])
}

func sortDurations(durations []time.Duration) {
	for i := 0; i < len(durations); i++ {
		for j := i + 1; j < len(durations); j++ {
			if durations[i] > durations[j] {
				durations[i], durations[j] = durations[j], durations[i]
			}
		}
	}
}
