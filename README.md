# ZERO
A kernel bypass networking research project proving that 
BPF-based packet capture achieves sub-microsecond latency 
vs standard sockets. Transport layer in progress.

## Results

### Loopback (ln0)
| Metric      | Standard Socket | ZERO (BPF)   | Improvement  |
|-------------|-----------------|--------------|--------------|
| Avg latency | 14,150 ns       | 49 ns        | 99.7% faster |
| P50 latency | 13,042 ns       | 41 ns        | 99.7% faster |
| P99 latency | 39,041 ns       | 125 ns       | 99.7% faster |
| Throughput  | 69,228 pkt/s    | 91,333 pkt/s | 32% higher   |
| Data rate   | 0.26 MB/s       | 3.14 MB/s    | 12x higher   |

### Real NIC (en0)
| Metric      | Standard Socket | ZERO (BPF) | Improvement  |
|-------------|-----------------|------------|--------------|
| Avg latency | 99,485 ns       | 627 ns     | 99.4% faster |
| P50 latency | 100,208 ns      | 334 ns     | 99.7% faster |
| P99 latency | 140,792 ns      | 5,667 ns   | 96% faster   |

## Architecture
```
+-------------------------+
|  Application Layer      |  (User-facing API)
|  - zero.Connect()       |
|  - zero.Send()          |
|  - zero.Receive()       |
+-------------------------+
|  Abstraction Layer      |  (Simplifies Aeron + BPF usage)
|  - Wraps Aeron API      |
|  - Manages sessions     |
|  - Ensures reliability  |
+-------------------------+
|  Transport Layer        |  (Aeron for userspace transport)
|  - Media Driver         |
|  - Publication/Sub      |
|  - Reliability (ACKs)   |
+-------------------------+
|  Kernel Bypass Layer    |  (BPF for packet filtering)
|  - BPF filtering        |
|  - Raw packet capture   |
|  - Direct NIC access    |
+-------------------------+
|  Network (NIC)          |  (Hardware Layer)
+-------------------------+

```

## Run the benchmarks yourself
cd perf
sudo go run ln0_perf_comparision.go
sudo go run en0_perf_comparision.go
<!--   

```
ZERO/
├── cmd/
│   ├── perftest/
│   │   ├── main.go            # Entry point for performance testing
│   │   ├── pcap_test.go       # BPF/pcap performance tests
│   │   └── socket_test.go     # Standard socket performance tests
│   └── examples/
│       ├── echo/
│       │   └── main.go        # Simple echo server/client example
│       └── pubsub/
│           └── main.go        # Publish/subscribe pattern example
├── internal/
│   ├── bpf/
│   │   ├── capture.go         # Packet capture implementation
│   │   ├── filter.go          # BPF filter optimization
│   │   └── stats.go           # Performance statistics collection
│   ├── transport/
│   │   ├── aeron.go           # Aeron integration
│   │   ├── buffer_pool.go     # Memory management and buffer pooling
│   │   ├── reliability.go     # Reliability layer implementation
│   │   └── session.go         # Session management
│   └── platform/
│       ├── macos.go           # macOS-specific optimizations
│       └── common.go          # Platform-agnostic utilities
├── pkg/
│   ├── zero/
│   │   ├── api.go             # Public API definitions
│   │   ├── config.go          # Configuration options
│   │   ├── connect.go         # Connection establishment
│   │   ├── receive.go         # Message reception
│   │   ├── send.go            # Message transmission
│   │   └── types.go           # Common type definitions
│   └── metrics/
│       ├── latency.go         # Latency measurement utilities
│       └── throughput.go      # Throughput measurement utilities
├── perf/
│   ├── en0_perf_comparision.go  # Your existing NIC performance test
│   └── ln0_perf_comparision.go  # Your existing loopback performance test
├── test/
│   ├── integration/           # Integration tests
│   │   └── e2e_test.go        # End-to-end tests
│   └── benchmark/             # Benchmark tests
│       └── latency_bench_test.go  # Latency benchmarks
├── go.mod
├── go.sum
└── README.md

```
-->
