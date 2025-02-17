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
