# ZERO

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


```
ZERO/
├── cmd/
│   └── zeropoc/
│       └── main.go            # Main entry point for the POC
├── internal/
│   ├── capture/
│   │   └── bpf.go             # BPF packet capture implementation
│   └── transport/
│       └── aeron.go           # Basic Aeron integration
├── pkg/
│   └── zero/
│       ├── zero.go            # Simplified public API
│       └── config.go          # Basic configuration
├── examples/
│   └── simple_echo.go         # Demonstrates basic functionality
├── perf/
│   ├── en0_perf_comparision.go  # Your existing NIC performance test
│   └── ln0_perf_comparision.go  # Your existing loopback performance test
├── go.mod
├── go.sum
└── README.md
```
