# ZERO

```

+-------------------------+
|  Application Layer      |  (User implements this)   
+-------------------------+
| (Optional) Session Layer|
|  - Basic connection mgmt|
|  - Session tracking     |
+-------------------------+
|  Transport Layer        |
|  - Aeron / Custom UDP   |
|  - Reliability (ACKs)  |
|  - Flow control         |
+-------------------------+
|  Raw Packet Handling    |
|  - BPF / pcap           |
|  - Zero-copy IPC        |
|  - Packet filtering     |
+-------------------------+
|  Network (NIC)          |
+-------------------------+
```
