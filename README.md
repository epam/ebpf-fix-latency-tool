# fixlat-kfifo (IP+Port filter)

**Summary**

`fixlat-kfifo` is a lightweight eBPF-based latency measurement tool designed to correlate inbound and outbound FIX protocol messages **entirely inside the Linux kernel**. It observes TCP packets on a given interface and matches messages by FIX Tag 11 (Client Order ID). For each correlated request–response pair, it computes latency (in microseconds) and updates an in-kernel **log2 histogram**. The histogram can be periodically read and reset from user space, allowing real-time latency distribution tracking with near-zero overhead.

This version adds a **bidirectional IP + TCP port filter**, so only traffic to/from a specific host and port pair is analyzed. The filter can be disabled by setting IP or port to zero.

**Core features:**

* Entire correlation logic runs in kernel space (no userspace packet processing).
* FIFO queue (`BPF_MAP_TYPE_QUEUE`) buffers pending inbound requests.
* Outbound responses pop from the queue until Tag 11 matches.
* In-kernel HDR-style histogram (log2 buckets, µs resolution).
* Userspace utility attaches tc filters, polls histogram, and prints percentiles.
* Bidirectional filtering by one IPv4 address and TCP port.
* Clean detachment with provided script.

---

## Build

```bash
sudo apt update
sudo apt install -y clang llvm make cmake pkg-config libelf-dev libbpf-dev bpftool
mkdir build && cd build
cmake ..
make -j
```

## Run

```bash
# Watch IP 10.0.0.5 and port 9898 on interface eno1
sudo ./fixlat -i eno1 -a 10.0.0.5 -p 9898 -r 5
```

Ignore filters by passing zeros:

```bash
sudo ./fixlat -i eno1 -a 0.0.0.0 -p 0
```

Each line of output represents one histogram snapshot:

```
[fixlat-kfifo] matched=25000 inbound=25210 outbound=25180 fifo_missed=3 unmatched_out=0  p50=12us p90=17us p99=36us p99.9=64us
```

## Detach

```bash
sudo tc qdisc del dev <iface> clsact 2>/dev/null || true
```
