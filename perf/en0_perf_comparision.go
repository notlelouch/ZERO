// Network interface performance comparison between BPF filter (pcap) vs standard socket.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	udpPort       = 54321
	packetRate    = 10000 // 10,000 packets/sec - more realistic for physical network
	benchDuration = 10 * time.Second
	packetSize    = 512 // bytes - more realistic packet size
)

func main() {
	// Parse command line flags
	interfaceName := flag.String("interface", "en0", "Network interface to use")
	senderIP := flag.String("sender", "", "IP address to send packets from (default: auto-detect)")
	targetIP := flag.String("target", "", "IP address to send packets to (default: auto-detect broadcast)")
	mode := flag.String("mode", "both", "Benchmark mode: 'pcap', 'socket', or 'both'")
	flag.Parse()

	// Get interface info
	iface, sourceIP, destIP, err := getInterfaceInfo(*interfaceName, *senderIP, *targetIP)
	if err != nil {
		log.Fatalf("Error setting up interface: %v", err)
	}

	fmt.Printf("Using interface: %s\n", iface.Name)
	fmt.Printf("Source IP: %s\n", sourceIP)
	fmt.Printf("Target IP: %s\n", destIP)

	// Set up signal handling for clean shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\nShutting down...")
		os.Exit(0)
	}()

	// Run selected benchmark mode
	switch *mode {
	case "both":
		runPcapBenchmark(iface.Name, sourceIP, destIP)
		time.Sleep(1 * time.Second) // Allow network to stabilize
		runSocketBenchmark(sourceIP, destIP)
	case "pcap":
		runPcapBenchmark(iface.Name, sourceIP, destIP)
	case "socket":
		runSocketBenchmark(sourceIP, destIP)
	default:
		log.Fatalf("Invalid mode: %s. Use 'pcap', 'socket', or 'both'", *mode)
	}
}

func getInterfaceInfo(interfaceName, senderIP, targetIP string) (net.Interface, string, string, error) {
	// Find the specified interface
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return net.Interface{}, "", "", fmt.Errorf("interface not found: %v", err)
	}

	// Get interface addresses
	addrs, err := iface.Addrs()
	if err != nil {
		return net.Interface{}, "", "", fmt.Errorf("failed to get interface addresses: %v", err)
	}

	// Find a suitable IPv4 address
	var sourceIP string
	var broadcastIP string
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipv4 := ipnet.IP.To4(); ipv4 != nil {
				sourceIP = ipv4.String()

				// Calculate broadcast address from IP and netmask
				// This is a simple calculation that works for most common network masks
				mask := ipnet.Mask
				broadcastIP = calculateBroadcast(ipv4, mask).String()
				break
			}
		}
	}

	if sourceIP == "" {
		return net.Interface{}, "", "", fmt.Errorf("no suitable IPv4 address found on interface %s", interfaceName)
	}

	// Override source IP if specified
	if senderIP != "" {
		sourceIP = senderIP
	}

	// Override target IP if specified
	finalTargetIP := broadcastIP
	if targetIP != "" {
		finalTargetIP = targetIP
	}

	return *iface, sourceIP, finalTargetIP, nil
}

func calculateBroadcast(ip net.IP, mask net.IPMask) net.IP {
	broadcast := make(net.IP, len(ip))
	for i := 0; i < len(ip); i++ {
		broadcast[i] = ip[i] | ^mask[i]
	}
	return broadcast
}

func runPcapBenchmark(interfaceName, sourceIP, targetIP string) {
	// Start the traffic generator
	donePCAP := make(chan bool)
	go generateUDPTraffic(donePCAP, sourceIP, targetIP, packetSize)
	time.Sleep(500 * time.Millisecond) // Let traffic generator initialize

	fmt.Println("Running pcap/BPF benchmark...")
	benchmarkPcap(interfaceName, targetIP)

	donePCAP <- true
	time.Sleep(500 * time.Millisecond) // Allow cleanup
}

func runSocketBenchmark(sourceIP, targetIP string) {
	// Start the traffic generator
	doneSocket := make(chan bool)
	go generateUDPTraffic(doneSocket, sourceIP, targetIP, packetSize)
	time.Sleep(500 * time.Millisecond)

	fmt.Println("\nRunning standard socket benchmark...")
	benchmarkStandardSocket()

	doneSocket <- true
}

func generateUDPTraffic(done chan bool, sourceIP, targetIP string, size int) {
	// Explicitly bind to source IP if needed
	localAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", sourceIP))
	if err != nil {
		log.Printf("Failed to resolve local address: %v", err)
		return
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", targetIP, udpPort))
	if err != nil {
		log.Printf("Failed to resolve remote address: %v", err)
		return
	}

	conn, err := net.DialUDP("udp", localAddr, remoteAddr)
	if err != nil {
		log.Printf("UDP sender failed: %v", err)
		return
	}
	defer conn.Close()

	// Create a packet of the specified size
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 256)
	}

	// Use ticker for more accurate timing
	ticker := time.NewTicker(time.Second / time.Duration(packetRate))
	defer ticker.Stop()

	packetsSent := 0
	startTime := time.Now()

	fmt.Printf("Sending packets from %s to %s:%d\n", sourceIP, targetIP, udpPort)

	for {
		select {
		case <-done:
			duration := time.Since(startTime)
			actualRate := float64(packetsSent) / duration.Seconds()
			fmt.Printf("Traffic generator: sent %d packets (%.2f packets/sec)\n",
				packetsSent, actualRate)
			return
		case <-ticker.C:
			if _, err := conn.Write(data); err != nil {
				log.Printf("Error sending packet: %v", err)
			}
			packetsSent++
		}
	}
}

func benchmarkPcap(interfaceName, targetIP string) {
	// Open device with a very short timeout instead of blocking forever
	// This allows more frequent polling
	handle, err := pcap.OpenLive(interfaceName, 65535, true, 1*time.Millisecond)
	if err != nil {
		log.Fatalf("Failed to open device: %v", err)
	}
	defer handle.Close()

	// Set BPF filter - only capture traffic for our benchmark
	filter := fmt.Sprintf("udp and port %d", udpPort)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("BPF filter failed: %v", err)
	}

	fmt.Printf("Capturing with filter: %s\n", filter)

	var (
		packets    int
		totalBytes int
		times      []time.Duration
		start      = time.Now()
		deadline   = start.Add(benchDuration)
	)

	// Force garbage collection before benchmark
	runtime.GC()

	// Use direct packet reading instead of channels for better performance
	for time.Now().Before(deadline) {
		// Use ZeroCopyReadPacketData for better performance
		data, _, err := handle.ZeroCopyReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			log.Printf("Error reading packet: %v", err)
			continue
		}

		processStart := time.Now()
		// Process packet data directly
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			if int(udp.DstPort) == udpPort || int(udp.SrcPort) == udpPort {
				packets++
				totalBytes += len(data)
				times = append(times, time.Since(processStart))
			}
		}
	}

	printStats("PCAP/BPF", packets, totalBytes, times, time.Since(start))
}

//	func benchmarkPcap(interfaceName, targetIP string) {
//		// Open device
//		handle, err := pcap.OpenLive(interfaceName, 65535, true, pcap.BlockForever)
//		if err != nil {
//			log.Fatalf("Failed to open device: %v", err)
//		}
//		defer handle.Close()
//
//		// Set BPF filter - only capture traffic for our benchmark
//		filter := fmt.Sprintf("udp and port %d", udpPort)
//		if err := handle.SetBPFFilter(filter); err != nil {
//			log.Fatalf("BPF filter failed: %v", err)
//		}
//
//		fmt.Printf("Capturing with filter: %s\n", filter)
//
//		var (
//			packets    int
//			totalBytes int
//			times      []time.Duration
//			start      = time.Now()
//			deadline   = start.Add(benchDuration)
//		)
//
//		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
//		packetChan := packetSource.Packets()
//
//		// Force garbage collection before benchmark
//		runtime.GC()
//
//		for {
//			if time.Now().After(deadline) {
//				break
//			}
//
//			select {
//			case packet := <-packetChan:
//				if packet == nil {
//					continue
//				}
//
//				processStart := time.Now()
//				if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
//					udp, _ := udpLayer.(*layers.UDP)
//					if int(udp.DstPort) == udpPort || int(udp.SrcPort) == udpPort {
//						packets++
//						totalBytes += len(packet.Data())
//						times = append(times, time.Since(processStart))
//					}
//				}
//
//			case <-time.After(10 * time.Millisecond):
//				// Short timeout to check deadline more frequently
//			}
//		}
//
//		printStats("PCAP/BPF", packets, totalBytes, times, time.Since(start))
//	}
func benchmarkStandardSocket() {
	// Bind to UDP port
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", udpPort))
	if err != nil {
		log.Fatalf("Failed to resolve address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("Failed to create UDP socket: %v", err)
	}
	defer conn.Close()

	var (
		packets    int
		totalBytes int
		times      []time.Duration
		start      = time.Now()
		deadline   = start.Add(benchDuration)
		buf        = make([]byte, 65535)
	)

	// Force garbage collection before benchmark
	runtime.GC()

	for time.Now().Before(deadline) {
		conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		processStart := time.Now()

		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("Error reading from UDP: %v", err)
			continue
		}

		packets++
		totalBytes += n
		times = append(times, time.Since(processStart))
	}

	printStats("Standard Socket", packets, totalBytes, times, time.Since(start))
}

func printStats(name string, packets, bytes int, times []time.Duration, duration time.Duration) {
	if len(times) == 0 {
		fmt.Printf("--- %s Results ---\nNo packets captured\n", name)
		return
	}

	// Use Go's built-in sort instead of bubble sort
	sort.Slice(times, func(i, j int) bool {
		return times[i] < times[j]
	})

	var totalLatency time.Duration
	for _, t := range times {
		totalLatency += t
	}

	avgLatency := totalLatency / time.Duration(len(times))
	packetsPerSec := float64(packets) / duration.Seconds()
	expectedPackets := packetRate * duration.Seconds()
	packetLoss := 100.0 - (float64(packets) / expectedPackets * 100.0)

	fmt.Printf("--- %s Results ---\n", name)
	fmt.Printf("Test duration: %.2f seconds\n", duration.Seconds())
	fmt.Printf("Packets captured: %d\n", packets)
	fmt.Printf("Capture rate: %.2f packets/sec\n", packetsPerSec)
	fmt.Printf("Packet loss: %.2f%%\n", packetLoss)
	fmt.Printf("Data rate: %.2f MB/sec\n", float64(bytes)/(1024*1024)/duration.Seconds())
	fmt.Printf("Average latency: %v\n", avgLatency)
	fmt.Printf("Min latency: %v\n", times[0])
	fmt.Printf("P50 latency: %v\n", times[len(times)*50/100])
	fmt.Printf("P95 latency: %v\n", times[len(times)*95/100])
	fmt.Printf("P99 latency: %v\n", times[len(times)*99/100])
	fmt.Printf("Max latency: %v\n", times[len(times)-1])
}
