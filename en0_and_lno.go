// package main
//
// import (
// 	"flag"
// 	"fmt"
// 	"log"
// 	"net"
// 	"os"
// 	"time"
//
// 	"github.com/google/gopacket"
// 	"github.com/google/gopacket/layers"
// 	"github.com/google/gopacket/pcap"
// )
//
// const (
// 	udpPort       = 54321
// 	packetRateLo  = 100000 // 100k packets/sec for loopback
// 	packetRateEn  = 10000  // 10k packets/sec for physical interface
// 	payloadSize   = 1024   // bytes
// 	testDuration  = 5      // seconds
// 	setupWaitTime = 200    // milliseconds
// )
//
// // Custom packet stats structure since pcap.PacketStats might not be available
// type PacketStats struct {
// 	PacketsReceived int
// 	PacketsDropped  int
// }
//
// type TestConfig struct {
// 	interfaceName  string
// 	targetIP       string
// 	isLocalNetwork bool
// 	packetRate     int
// }
//
// func main() {
// 	// Parse command line flags
// 	interfacePtr := flag.String("interface", "", "Network interface to test (default: auto-detect)")
// 	targetIPPtr := flag.String("target", "", "Target IP address (default: auto-detect)")
// 	flag.Parse()
//
// 	// Auto-detect interfaces and configure tests
// 	configs, err := setupTestConfigurations(*interfacePtr, *targetIPPtr)
// 	if err != nil {
// 		log.Fatalf("Failed to setup test configurations: %v", err)
// 	}
//
// 	// Run tests for each configuration
// 	for _, config := range configs {
// 		fmt.Printf("\n========== TESTING INTERFACE: %s (Target IP: %s) ==========\n",
// 			config.interfaceName, config.targetIP)
//
// 		// Benchmark PCAP/BPF
// 		fmt.Printf("\nRunning pcap/BPF benchmark on %s...\n", config.interfaceName)
//
// 		// Create channels for communication
// 		pcapReady := make(chan bool)
// 		donePCAP := make(chan bool)
// 		pcapFinished := make(chan bool)
//
// 		// Start PCAP listener first in its own goroutine
// 		go func() {
// 			benchmarkPcap(config, pcapReady, donePCAP)
// 			pcapFinished <- true
// 		}()
//
// 		// Wait for PCAP listener to be ready
// 		<-pcapReady
//
// 		// Start traffic generator in its own goroutine
// 		go generateUDPTraffic(donePCAP, config.targetIP, config.packetRate)
//
// 		// Wait for PCAP test to finish
// 		<-pcapFinished
//
// 		// Small pause between tests
// 		time.Sleep(time.Second * 2)
//
// 		// Benchmark Socket
// 		fmt.Printf("\nRunning standard socket benchmark on %s...\n", config.interfaceName)
//
// 		// Create new channels for the socket test
// 		socketReady := make(chan bool)
// 		doneSocket := make(chan bool)
// 		socketFinished := make(chan bool)
//
// 		// Start socket listener first
// 		go func() {
// 			benchmarkStandardSocket(config, socketReady, doneSocket)
// 			socketFinished <- true
// 		}()
//
// 		// Wait for socket listener to be ready
// 		<-socketReady
//
// 		// Start traffic generator
// 		go generateUDPTraffic(doneSocket, config.targetIP, config.packetRate)
//
// 		// Wait for socket test to finish
// 		<-socketFinished
// 	}
// }
//
// func setupTestConfigurations(requestedInterface, requestedIP string) ([]TestConfig, error) {
// 	configs := []TestConfig{}
//
// 	// Always include loopback interface test
// 	loConfig := TestConfig{
// 		interfaceName:  "lo0",
// 		targetIP:       "127.0.0.1",
// 		isLocalNetwork: true,
// 		packetRate:     packetRateLo,
// 	}
// 	configs = append(configs, loConfig)
//
// 	// Find physical interface if not specified
// 	var physicalInterfaceName, physicalInterfaceIP string
//
// 	if requestedInterface != "" && requestedIP != "" {
// 		// Use user-provided values
// 		physicalInterfaceName = requestedInterface
// 		physicalInterfaceIP = requestedIP
// 	} else {
// 		// Auto-detect best physical interface
// 		interfaces, err := net.Interfaces()
// 		if err != nil {
// 			return configs, fmt.Errorf("failed to get network interfaces: %v", err)
// 		}
//
// 		for _, iface := range interfaces {
// 			// Skip loopback, inactive, or non-ethernet interfaces
// 			if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
// 				continue
// 			}
//
// 			addrs, err := iface.Addrs()
// 			if err != nil {
// 				continue
// 			}
//
// 			for _, addr := range addrs {
// 				ipNet, ok := addr.(*net.IPNet)
// 				if !ok || ipNet.IP.IsLoopback() || ipNet.IP.To4() == nil {
// 					continue
// 				}
//
// 				// Found a suitable physical interface
// 				physicalInterfaceName = iface.Name
// 				physicalInterfaceIP = ipNet.IP.String()
// 				break
// 			}
//
// 			if physicalInterfaceName != "" {
// 				break
// 			}
// 		}
// 	}
//
// 	// If we found a physical interface, add it to configs
// 	if physicalInterfaceName != "" {
// 		enConfig := TestConfig{
// 			interfaceName:  physicalInterfaceName,
// 			targetIP:       physicalInterfaceIP,
// 			isLocalNetwork: false,
// 			packetRate:     packetRateEn,
// 		}
// 		configs = append(configs, enConfig)
// 	} else {
// 		fmt.Println("Warning: Could not find a suitable physical network interface.")
// 		fmt.Println("Running tests on loopback interface only.")
// 	}
//
// 	return configs, nil
// }
//
// func generateUDPTraffic(done <-chan bool, targetIP string, rate int) {
// 	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
// 		IP:   net.ParseIP(targetIP),
// 		Port: udpPort,
// 	})
// 	if err != nil {
// 		log.Printf("UDP sender failed: %v", err)
// 		return
// 	}
// 	defer conn.Close()
//
// 	// Create a test payload of specified size
// 	data := make([]byte, payloadSize)
// 	for i := range data {
// 		data[i] = byte(i % 256)
// 	}
//
// 	// Calculate interval between packets
// 	interval := time.Second / time.Duration(rate)
// 	ticker := time.NewTicker(interval)
// 	defer ticker.Stop()
//
// 	counter := 0
// 	startTime := time.Now()
// 	retryCount := 0
// 	maxRetries := 5
//
// 	for {
// 		select {
// 		case <-done:
// 			duration := time.Since(startTime)
// 			actualRate := float64(counter) / duration.Seconds()
// 			log.Printf("Traffic generator finished: sent %d packets at %.2f packets/sec\n",
// 				counter, actualRate)
// 			return
// 		case <-ticker.C:
// 			// Add sequence number and timestamp to first bytes of payload
// 			counter++
// 			timestamp := time.Now().UnixNano()
//
// 			// Write sequence number (first 4 bytes)
// 			data[0] = byte(counter >> 24)
// 			data[1] = byte(counter >> 16)
// 			data[2] = byte(counter >> 8)
// 			data[3] = byte(counter)
//
// 			// Write timestamp (next 8 bytes)
// 			data[4] = byte(timestamp >> 56)
// 			data[5] = byte(timestamp >> 48)
// 			data[6] = byte(timestamp >> 40)
// 			data[7] = byte(timestamp >> 32)
// 			data[8] = byte(timestamp >> 24)
// 			data[9] = byte(timestamp >> 16)
// 			data[10] = byte(timestamp >> 8)
// 			data[11] = byte(timestamp)
//
// 			_, err := conn.Write(data)
// 			if err != nil {
// 				if retryCount < maxRetries {
// 					retryCount++
// 					time.Sleep(50 * time.Millisecond)
// 					continue
// 				}
// 				log.Printf("Error sending packet: %v", err)
// 			} else {
// 				retryCount = 0 // Reset retry counter on success
// 			}
// 		}
// 	}
// }
//
// func benchmarkPcap(config TestConfig, ready chan<- bool, done chan<- bool) {
// 	// Open device
// 	handle, err := pcap.OpenLive(
// 		config.interfaceName,
// 		65535,
// 		true,
// 		pcap.BlockForever,
// 	)
// 	if err != nil {
// 		log.Fatalf("Failed to open device %s: %v", config.interfaceName, err)
// 	}
// 	defer handle.Close()
//
// 	// Set BPF filter
// 	filterString := fmt.Sprintf("udp and port %d", udpPort)
// 	if err := handle.SetBPFFilter(filterString); err != nil {
// 		log.Fatalf("BPF filter '%s' failed: %v", filterString, err)
// 	}
//
// 	log.Printf("PCAP capture started on %s with filter: %s", config.interfaceName, filterString)
//
// 	// Signal that the pcap listener is ready
// 	ready <- true
//
// 	var (
// 		packets     int
// 		totalBytes  int
// 		start       = time.Now()
// 		deadline    = start.Add(time.Duration(testDuration) * time.Second)
// 		latencies   = make([]time.Duration, 0, config.packetRate*testDuration)
// 		lastSeq     int
// 		outOfOrder  int
// 		duplicates  int
// 		seenPackets = make(map[int]bool)
// 	)
//
// 	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
// 	packetChan := packetSource.Packets()
//
// 	// Process packets until deadline
// 	for time.Now().Before(deadline) {
// 		select {
// 		case packet := <-packetChan:
// 			if packet == nil {
// 				continue
// 			}
//
// 			if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
// 				udp, _ := udpLayer.(*layers.UDP)
// 				if int(udp.DstPort) != udpPort {
// 					continue
// 				}
//
// 				// Extract application payload
// 				applicationLayer := packet.ApplicationLayer()
// 				if applicationLayer == nil || len(applicationLayer.Payload()) < 12 {
// 					continue // Skip malformed packets
// 				}
//
// 				packets++
// 				totalBytes += len(packet.Data())
//
// 				// Extract sequence number and timestamp
// 				payload := applicationLayer.Payload()
// 				seq := int(uint32(payload[0])<<24 | uint32(payload[1])<<16 |
// 					uint32(payload[2])<<8 | uint32(payload[3]))
// 				sendTime := int64(uint64(payload[4])<<56 | uint64(payload[5])<<48 |
// 					uint64(payload[6])<<40 | uint64(payload[7])<<32 |
// 					uint64(payload[8])<<24 | uint64(payload[9])<<16 |
// 					uint64(payload[10])<<8 | uint64(payload[11]))
//
// 				// Calculate latency
// 				latency := time.Duration(time.Now().UnixNano() - sendTime)
// 				latencies = append(latencies, latency)
//
// 				// Check for out-of-order packets and duplicates
// 				if seenPackets[seq] {
// 					duplicates++
// 				} else {
// 					seenPackets[seq] = true
// 				}
//
// 				if seq < lastSeq && lastSeq > 0 {
// 					outOfOrder++
// 				}
// 				lastSeq = seq
// 			}
//
// 		case <-time.After(10 * time.Millisecond):
// 			// Just to prevent blocking forever
// 			continue
// 		}
// 	}
//
// 	// Signal traffic generator to stop
// 	done <- true
//
// 	// Try to get packet statistics if supported
// 	var droppedInfo PacketStats
// 	stats, err := handle.Stats()
// 	if err == nil {
// 		droppedInfo.PacketsReceived = stats.PacketsReceived
// 		droppedInfo.PacketsDropped = stats.PacketsDropped
// 	}
//
// 	printDetailedStats("PCAP/BPF", config, packets, totalBytes, latencies,
// 		time.Since(start), droppedInfo, outOfOrder, duplicates)
// }
//
// func benchmarkStandardSocket(config TestConfig, ready chan<- bool, done chan<- bool) {
// 	// Bind to UDP port directly
// 	addr := &net.UDPAddr{Port: udpPort}
// 	if config.isLocalNetwork {
// 		addr.IP = net.ParseIP("127.0.0.1")
// 	} else {
// 		// For a physical interface, bind to the interface IP
// 		addr.IP = net.ParseIP(config.targetIP)
// 	}
//
// 	conn, err := net.ListenUDP("udp", addr)
// 	if err != nil {
// 		log.Fatalf("Failed to create UDP socket: %v", err)
// 	}
// 	defer conn.Close()
//
// 	// Try to increase buffer size
// 	err = conn.SetReadBuffer(1024 * 1024 * 8) // 8MB buffer
// 	if err != nil {
// 		log.Printf("Warning: Failed to increase socket buffer size: %v", err)
// 	}
//
// 	// Signal that the socket listener is ready
// 	ready <- true
//
// 	var (
// 		packets     int
// 		totalBytes  int
// 		start       = time.Now()
// 		deadline    = start.Add(time.Duration(testDuration) * time.Second)
// 		latencies   = make([]time.Duration, 0, config.packetRate*testDuration)
// 		buf         = make([]byte, 65535)
// 		lastSeq     int
// 		outOfOrder  int
// 		duplicates  int
// 		seenPackets = make(map[int]bool)
// 	)
//
// 	for time.Now().Before(deadline) {
// 		conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
// 		n, _, err := conn.ReadFromUDP(buf)
// 		if err != nil {
// 			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
// 				continue
// 			}
// 			log.Printf("ReadFromUDP error: %v", err)
// 			continue
// 		}
//
// 		if n < 12 {
// 			continue // Skip malformed packets
// 		}
//
// 		// Extract sequence number and timestamp
// 		seq := int(uint32(buf[0])<<24 | uint32(buf[1])<<16 |
// 			uint32(buf[2])<<8 | uint32(buf[3]))
// 		sendTime := int64(uint64(buf[4])<<56 | uint64(buf[5])<<48 |
// 			uint64(buf[6])<<40 | uint64(buf[7])<<32 |
// 			uint64(buf[8])<<24 | uint64(buf[9])<<16 |
// 			uint64(buf[10])<<8 | uint64(buf[11]))
//
// 		// Calculate latency
// 		latency := time.Duration(time.Now().UnixNano() - sendTime)
// 		latencies = append(latencies, latency)
//
// 		packets++
// 		totalBytes += n
//
// 		// Check for out-of-order packets and duplicates
// 		if seenPackets[seq] {
// 			duplicates++
// 		} else {
// 			seenPackets[seq] = true
// 		}
//
// 		if seq < lastSeq && lastSeq > 0 {
// 			outOfOrder++
// 		}
// 		lastSeq = seq
// 	}
//
// 	// Signal traffic generator to stop
// 	done <- true
//
// 	// No packet drop stats available for standard sockets
// 	var droppedInfo PacketStats
//
// 	printDetailedStats("Standard Socket", config, packets, totalBytes, latencies,
// 		time.Since(start), droppedInfo, outOfOrder, duplicates)
// }
//
// func printDetailedStats(name string, config TestConfig, packets, bytes int,
// 	latencies []time.Duration, duration time.Duration,
// 	drops PacketStats, outOfOrder, duplicates int,
// ) {
// 	if len(latencies) == 0 {
// 		fmt.Printf("--- %s Results on %s ---\nNo packets captured\n",
// 			name, config.interfaceName)
// 		return
// 	}
//
// 	sortDurations(latencies)
//
// 	var totalLatency time.Duration
// 	for _, t := range latencies {
// 		totalLatency += t
// 	}
//
// 	avgLatency := totalLatency / time.Duration(len(latencies))
//
// 	// Calculate jitter (variation in latency)
// 	var jitterSum time.Duration
// 	var prevLatency time.Duration
//
// 	if len(latencies) > 0 {
// 		prevLatency = latencies[0]
// 	}
//
// 	for _, latency := range latencies[1:] {
// 		if latency > prevLatency {
// 			jitterSum += latency - prevLatency
// 		} else {
// 			jitterSum += prevLatency - latency
// 		}
// 		prevLatency = latency
// 	}
//
// 	avgJitter := time.Duration(0)
// 	if len(latencies) > 1 {
// 		avgJitter = jitterSum / time.Duration(len(latencies)-1)
// 	}
//
// 	fmt.Printf("\n====== %s Results on %s ======\n", name, config.interfaceName)
// 	fmt.Printf("Configuration:\n")
// 	fmt.Printf("  - Interface: %s\n", config.interfaceName)
// 	fmt.Printf("  - Target IP: %s\n", config.targetIP)
// 	fmt.Printf("  - Packet rate: %d packets/sec\n", config.packetRate)
// 	fmt.Printf("  - Payload size: %d bytes\n", payloadSize)
// 	fmt.Printf("\nPerformance metrics:\n")
// 	fmt.Printf("  - Test duration: %.2f seconds\n", duration.Seconds())
// 	fmt.Printf("  - Packets expected: %d\n", int(duration.Seconds()*float64(config.packetRate)))
// 	fmt.Printf("  - Packets captured: %d\n", packets)
// 	fmt.Printf("  - Packet loss: %.2f%%\n", 100-float64(packets)/
// 		(duration.Seconds()*float64(config.packetRate))*100)
//
// 	if drops.PacketsReceived > 0 || drops.PacketsDropped > 0 {
// 		fmt.Printf("  - Packets received by kernel: %d\n", drops.PacketsReceived)
// 		fmt.Printf("  - Packets dropped by kernel: %d (%.2f%%)\n",
// 			drops.PacketsDropped,
// 			float64(drops.PacketsDropped)/float64(drops.PacketsReceived+drops.PacketsDropped)*100)
// 	}
//
// 	fmt.Printf("  - Out-of-order packets: %d (%.2f%%)\n",
// 		outOfOrder, float64(outOfOrder)/float64(packets)*100)
// 	fmt.Printf("  - Duplicate packets: %d (%.2f%%)\n",
// 		duplicates, float64(duplicates)/float64(packets)*100)
// 	fmt.Printf("  - Throughput: %.2f packets/sec\n", float64(packets)/duration.Seconds())
// 	fmt.Printf("  - Data rate: %.2f Mbps\n",
// 		float64(bytes)*8/(1000*1000)/duration.Seconds())
//
// 	fmt.Printf("\nLatency metrics:\n")
// 	fmt.Printf("  - Average latency: %v\n", avgLatency)
// 	fmt.Printf("  - Average jitter: %v\n", avgJitter)
// 	fmt.Printf("  - Min latency: %v\n", latencies[0])
// 	fmt.Printf("  - P50 latency: %v\n", latencies[len(latencies)*50/100])
// 	fmt.Printf("  - P90 latency: %v\n", latencies[len(latencies)*90/100])
// 	fmt.Printf("  - P95 latency: %v\n", latencies[len(latencies)*95/100])
// 	fmt.Printf("  - P99 latency: %v\n", latencies[len(latencies)*99/100])
// 	fmt.Printf("  - Max latency: %v\n", latencies[len(latencies)-1])
//
// 	// Save results to CSV for further analysis
// 	saveResultsToCSV(name, config, packets, bytes, latencies, duration, drops, outOfOrder, duplicates)
// }
//
// func saveResultsToCSV(name string, config TestConfig, packets, bytes int,
// 	latencies []time.Duration, duration time.Duration,
// 	drops PacketStats, outOfOrder, duplicates int,
// ) {
// 	// Create filename based on test parameters
// 	filename := fmt.Sprintf("%s_%s_results.csv",
// 		config.interfaceName,
// 		sanitizeString(name))
//
// 	f, err := os.Create(filename)
// 	if err != nil {
// 		log.Printf("Failed to create CSV file: %v", err)
// 		return
// 	}
// 	defer f.Close()
//
// 	// Write summary data
// 	f.WriteString("Metric,Value\n")
// 	f.WriteString(fmt.Sprintf("Test,\"%s on %s\"\n", name, config.interfaceName))
// 	f.WriteString(fmt.Sprintf("Interface,%s\n", config.interfaceName))
// 	f.WriteString(fmt.Sprintf("Target IP,%s\n", config.targetIP))
// 	f.WriteString(fmt.Sprintf("Packet Rate,%d\n", config.packetRate))
// 	f.WriteString(fmt.Sprintf("Payload Size,%d\n", payloadSize))
// 	f.WriteString(fmt.Sprintf("Duration (sec),%.2f\n", duration.Seconds()))
// 	f.WriteString(fmt.Sprintf("Packets Expected,%d\n",
// 		int(duration.Seconds()*float64(config.packetRate))))
// 	f.WriteString(fmt.Sprintf("Packets Captured,%d\n", packets))
// 	f.WriteString(fmt.Sprintf("Packet Loss (%%),%.2f\n",
// 		100-float64(packets)/(duration.Seconds()*float64(config.packetRate))*100))
//
// 	if drops.PacketsReceived > 0 || drops.PacketsDropped > 0 {
// 		f.WriteString(fmt.Sprintf("Packets Received (kernel),%d\n", drops.PacketsReceived))
// 		f.WriteString(fmt.Sprintf("Packets Dropped (kernel),%d\n", drops.PacketsDropped))
// 		f.WriteString(fmt.Sprintf("Kernel Drop Rate (%%),%.2f\n",
// 			float64(drops.PacketsDropped)/float64(drops.PacketsReceived+drops.PacketsDropped)*100))
// 	}
//
// 	f.WriteString(fmt.Sprintf("Out Of Order Packets,%d\n", outOfOrder))
// 	f.WriteString(fmt.Sprintf("Duplicate Packets,%d\n", duplicates))
// 	f.WriteString(fmt.Sprintf("Throughput (packets/sec),%.2f\n", float64(packets)/duration.Seconds()))
// 	f.WriteString(fmt.Sprintf("Data Rate (Mbps),%.2f\n",
// 		float64(bytes)*8/(1000*1000)/duration.Seconds()))
//
// 	if len(latencies) > 0 {
// 		var totalLatency time.Duration
// 		for _, t := range latencies {
// 			totalLatency += t
// 		}
// 		avgLatency := totalLatency / time.Duration(len(latencies))
//
// 		f.WriteString(fmt.Sprintf("Average Latency (ns),%d\n", avgLatency.Nanoseconds()))
// 		f.WriteString(fmt.Sprintf("Min Latency (ns),%d\n", latencies[0].Nanoseconds()))
// 		f.WriteString(fmt.Sprintf("P50 Latency (ns),%d\n",
// 			latencies[len(latencies)*50/100].Nanoseconds()))
// 		f.WriteString(fmt.Sprintf("P90 Latency (ns),%d\n",
// 			latencies[len(latencies)*90/100].Nanoseconds()))
// 		f.WriteString(fmt.Sprintf("P95 Latency (ns),%d\n",
// 			latencies[len(latencies)*95/100].Nanoseconds()))
// 		f.WriteString(fmt.Sprintf("P99 Latency (ns),%d\n",
// 			latencies[len(latencies)*99/100].Nanoseconds()))
// 		f.WriteString(fmt.Sprintf("Max Latency (ns),%d\n",
// 			latencies[len(latencies)-1].Nanoseconds()))
// 	}
//
// 	// Write raw latency data to help with distribution analysis
// 	f.WriteString("\nRaw Latency Data (ns)\n")
// 	for i, latency := range latencies {
// 		f.WriteString(fmt.Sprintf("%d\n", latency.Nanoseconds()))
// 		if i > 10000 {
// 			// Limit to prevent huge files
// 			f.WriteString("...(truncated for file size)\n")
// 			break
// 		}
// 	}
//
// 	log.Printf("Results saved to %s", filename)
// }
//
// func sanitizeString(s string) string {
// 	result := ""
// 	for _, c := range s {
// 		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
// 			result += string(c)
// 		}
// 	}
// 	return result
// }
//
// func sortDurations(durations []time.Duration) {
// 	// Using insertion sort for better performance with partially sorted data
// 	for i := 1; i < len(durations); i++ {
// 		key := durations[i]
// 		j := i - 1
// 		for j >= 0 && durations[j] > key {
// 			durations[j+1] = durations[j]
// 			j--
// 		}
// 		durations[j+1] = key
// 	}
// }
