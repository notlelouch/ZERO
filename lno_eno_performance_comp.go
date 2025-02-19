// package main
//
// import (
// 	"flag"
// 	"fmt"
// 	"log"
// 	"net"
// 	"os"
// 	"os/signal"
// 	"sync"
// 	"syscall"
// 	"time"
//
// 	"github.com/google/gopacket"
// 	"github.com/google/gopacket/layers"
// 	"github.com/google/gopacket/pcap"
// )
//
// const (
// 	snapLen      = 2048
// 	testDuration = 10 * time.Second
// 	warmupTime   = 2 * time.Second
// 	cooldownTime = 2 * time.Second
// 	packetSize   = 1400
// 	batchSize    = 100
// 	sendInterval = 100 * time.Microsecond
// )
//
// var (
// 	targetIP  = flag.String("target", "", "Target IP address")
// 	ifaceName = flag.String("interface", "en0", "Network interface name")
// 	port      = flag.Int("port", 54321, "UDP port number")
// )
//
// type TestResult struct {
// 	PacketsReceived int64
// 	BytesReceived   int64
// 	Latencies       []time.Duration
// 	Duration        time.Duration
// }
//
// func main() {
// 	flag.Parse()
//
// 	if *targetIP == "" {
// 		log.Fatal("Please specify target IP with -target flag")
// 	}
//
// 	// Setup signal handling
// 	sigChan := make(chan os.Signal, 1)
// 	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
//
// 	// Run socket test
// 	fmt.Printf("\nRunning Standard Socket test...\n")
// 	socketResult := runSocketTest(sigChan)
// 	if socketResult == nil {
// 		log.Fatal("Socket test failed")
// 	}
// 	printResults("Socket", socketResult)
//
// 	// Wait between tests
// 	time.Sleep(cooldownTime)
//
// 	// Run BPF test
// 	fmt.Printf("\nRunning BPF test...\n")
// 	bpfResult := runBPFTest(sigChan)
// 	if bpfResult == nil {
// 		log.Fatal("BPF test failed")
// 	}
// 	printResults("BPF", bpfResult)
//
// 	// Compare results
// 	compareResults(socketResult, bpfResult)
// }
//
// func runSocketTest(sigChan chan os.Signal) *TestResult {
// 	var result TestResult
// 	var wg sync.WaitGroup
//
// 	// Create receiver channel and ready signal
// 	recvChan := make(chan struct{})
// 	readyChan := make(chan struct{})
//
// 	// Start receiver
// 	wg.Add(1)
// 	go func() {
// 		defer wg.Done()
// 		addr := &net.UDPAddr{Port: *port}
// 		conn, err := net.ListenUDP("udp", addr)
// 		if err != nil {
// 			log.Printf("Failed to create receiver: %v", err)
// 			return
// 		}
// 		defer conn.Close()
//
// 		// Signal ready
// 		close(readyChan)
//
// 		buffer := make([]byte, snapLen)
// 		start := time.Now()
// 		deadline := start.Add(testDuration)
//
// 		for time.Now().Before(deadline) {
// 			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
// 			n, _, err := conn.ReadFromUDP(buffer)
// 			if err != nil {
// 				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
// 					continue
// 				}
// 				log.Printf("Read error: %v", err)
// 				continue
// 			}
//
// 			result.PacketsReceived++
// 			result.BytesReceived += int64(n)
//
// 			if n >= 8 {
// 				ts := int64(buffer[0])<<56 | int64(buffer[1])<<48 |
// 					int64(buffer[2])<<40 | int64(buffer[3])<<32 |
// 					int64(buffer[4])<<24 | int64(buffer[5])<<16 |
// 					int64(buffer[6])<<8 | int64(buffer[7])
// 				result.Latencies = append(result.Latencies, time.Since(time.Unix(0, ts)))
// 			}
// 		}
// 		result.Duration = time.Since(start)
// 		close(recvChan)
// 	}()
//
// 	// Wait for receiver to be ready
// 	<-readyChan
//
// 	// Start sender
// 	wg.Add(1)
// 	go func() {
// 		defer wg.Done()
// 		addr := &net.UDPAddr{
// 			IP:   net.ParseIP(*targetIP),
// 			Port: *port,
// 		}
// 		conn, err := net.DialUDP("udp", nil, addr)
// 		if err != nil {
// 			log.Printf("Failed to create sender: %v", err)
// 			return
// 		}
// 		defer conn.Close()
//
// 		// Warm up period
// 		time.Sleep(warmupTime)
//
// 		ticker := time.NewTicker(sendInterval)
// 		defer ticker.Stop()
//
// 		payload := make([]byte, packetSize)
// 		for {
// 			select {
// 			case <-recvChan:
// 				return
// 			case <-sigChan:
// 				return
// 			case <-ticker.C:
// 				now := time.Now().UnixNano()
// 				// Add timestamp to first 8 bytes
// 				payload[0] = byte(now >> 56)
// 				payload[1] = byte(now >> 48)
// 				payload[2] = byte(now >> 40)
// 				payload[3] = byte(now >> 32)
// 				payload[4] = byte(now >> 24)
// 				payload[5] = byte(now >> 16)
// 				payload[6] = byte(now >> 8)
// 				payload[7] = byte(now)
//
// 				_, err := conn.Write(payload)
// 				if err != nil {
// 					continue
// 				}
// 			}
// 		}
// 	}()
//
// 	wg.Wait()
// 	return &result
// }
//
// func runBPFTest(sigChan chan os.Signal) *TestResult {
// 	var result TestResult
// 	var wg sync.WaitGroup
//
// 	// Create channels for coordination
// 	recvChan := make(chan struct{})
// 	readyChan := make(chan struct{})
//
// 	// Start receiver
// 	wg.Add(1)
// 	go func() {
// 		defer wg.Done()
// 		handle, err := pcap.OpenLive(*ifaceName, snapLen, true, 100*time.Millisecond)
// 		if err != nil {
// 			log.Printf("Failed to open pcap: %v", err)
// 			return
// 		}
// 		defer handle.Close()
//
// 		err = handle.SetBPFFilter(fmt.Sprintf("udp and port %d", *port))
// 		if err != nil {
// 			log.Printf("Failed to set BPF filter: %v", err)
// 			return
// 		}
//
// 		// Signal ready
// 		close(readyChan)
//
// 		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
// 		start := time.Now()
// 		deadline := start.Add(testDuration)
//
// 		for time.Now().Before(deadline) {
// 			packet, err := packetSource.NextPacket()
// 			if err != nil {
// 				continue
// 			}
//
// 			udpLayer := packet.Layer(layers.LayerTypeUDP)
// 			if udpLayer == nil {
// 				continue
// 			}
//
// 			udp, _ := udpLayer.(*layers.UDP)
// 			payload := udp.Payload
// 			if len(payload) >= 8 {
// 				ts := int64(payload[0])<<56 | int64(payload[1])<<48 |
// 					int64(payload[2])<<40 | int64(payload[3])<<32 |
// 					int64(payload[4])<<24 | int64(payload[5])<<16 |
// 					int64(payload[6])<<8 | int64(payload[7])
//
// 				result.PacketsReceived++
// 				result.BytesReceived += int64(len(payload))
// 				result.Latencies = append(result.Latencies, time.Since(time.Unix(0, ts)))
// 			}
// 		}
// 		result.Duration = time.Since(start)
// 		close(recvChan)
// 	}()
//
// 	// Wait for receiver to be ready
// 	<-readyChan
//
// 	// Start sender
// 	wg.Add(1)
// 	go func() {
// 		defer wg.Done()
// 		addr := &net.UDPAddr{
// 			IP:   net.ParseIP(*targetIP),
// 			Port: *port,
// 		}
// 		conn, err := net.DialUDP("udp", nil, addr)
// 		if err != nil {
// 			log.Printf("Failed to create sender: %v", err)
// 			return
// 		}
// 		defer conn.Close()
//
// 		// Warm up period
// 		time.Sleep(warmupTime)
//
// 		ticker := time.NewTicker(sendInterval)
// 		defer ticker.Stop()
//
// 		payload := make([]byte, packetSize)
// 		for {
// 			select {
// 			case <-recvChan:
// 				return
// 			case <-sigChan:
// 				return
// 			case <-ticker.C:
// 				now := time.Now().UnixNano()
// 				payload[0] = byte(now >> 56)
// 				payload[1] = byte(now >> 48)
// 				payload[2] = byte(now >> 40)
// 				payload[3] = byte(now >> 32)
// 				payload[4] = byte(now >> 24)
// 				payload[5] = byte(now >> 16)
// 				payload[6] = byte(now >> 8)
// 				payload[7] = byte(now)
//
// 				_, err := conn.Write(payload)
// 				if err != nil {
// 					continue
// 				}
// 			}
// 		}
// 	}()
//
// 	wg.Wait()
// 	return &result
// }
//
// func printResults(name string, result *TestResult) {
// 	fmt.Printf("\n=== %s Test Results ===\n", name)
// 	fmt.Printf("Duration: %.2f seconds\n", result.Duration.Seconds())
// 	fmt.Printf("Packets received: %d\n", result.PacketsReceived)
// 	fmt.Printf("Bytes received: %d\n", result.BytesReceived)
//
// 	if len(result.Latencies) > 0 {
// 		// Sort latencies for percentiles
// 		sortDurations(result.Latencies)
//
// 		fmt.Printf("Throughput: %.2f packets/sec\n",
// 			float64(result.PacketsReceived)/result.Duration.Seconds())
// 		fmt.Printf("Data rate: %.2f MB/sec\n",
// 			float64(result.BytesReceived)/(1024*1024)/result.Duration.Seconds())
// 		fmt.Printf("Latency (min/avg/p50/p95/p99/max):\n")
// 		fmt.Printf("  %.2f/%.2f/%.2f/%.2f/%.2f/%.2f ms\n",
// 			float64(result.Latencies[0])/float64(time.Millisecond),
// 			average(result.Latencies)/float64(time.Millisecond),
// 			float64(percentile(result.Latencies, 50))/float64(time.Millisecond),
// 			float64(percentile(result.Latencies, 95))/float64(time.Millisecond),
// 			float64(percentile(result.Latencies, 99))/float64(time.Millisecond),
// 			float64(result.Latencies[len(result.Latencies)-1])/float64(time.Millisecond))
// 	}
// }
//
// func compareResults(socket, bpf *TestResult) {
// 	fmt.Printf("\n=== Performance Comparison ===\n")
//
// 	socketThroughput := float64(socket.PacketsReceived) / socket.Duration.Seconds()
// 	bpfThroughput := float64(bpf.PacketsReceived) / bpf.Duration.Seconds()
//
// 	fmt.Printf("Throughput difference: %.2f%% (BPF vs Socket)\n",
// 		((bpfThroughput-socketThroughput)/socketThroughput)*100)
//
// 	if len(socket.Latencies) > 0 && len(bpf.Latencies) > 0 {
// 		socketLatencyP50 := float64(percentile(socket.Latencies, 50))
// 		bpfLatencyP50 := float64(percentile(bpf.Latencies, 50))
//
// 		fmt.Printf("Median latency difference: %.2f%% (BPF vs Socket)\n",
// 			((bpfLatencyP50-socketLatencyP50)/socketLatencyP50)*100)
// 	}
// }
//
// func sortDurations(durations []time.Duration) {
// 	for i := 0; i < len(durations)-1; i++ {
// 		for j := i + 1; j < len(durations); j++ {
// 			if durations[i] > durations[j] {
// 				durations[i], durations[j] = durations[j], durations[i]
// 			}
// 		}
// 	}
// }
//
// func percentile(sorted []time.Duration, p int) time.Duration {
// 	if len(sorted) == 0 {
// 		return 0
// 	}
// 	index := (len(sorted) - 1) * p / 100
// 	return sorted[index]
// }
//
// func average(durations []time.Duration) float64 {
// 	if len(durations) == 0 {
// 		return 0
// 	}
// 	var sum time.Duration
// 	for _, d := range durations {
// 		sum += d
// 	}
// 	return float64(sum) / float64(len(durations))
// }
