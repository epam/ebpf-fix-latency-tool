# ebpf-fix-latency-tool - eBPF FIX Protocol Latency Monitor

**Version 0.0.1**

**Latency measurement tool for FIX protocol traffic using eBPF TC hooks**

`ebpf-fix-latency-tool` is a lightweight eBPF-based tool that measures roundtrip latency for FIX protocol messages by correlating inbound requests with outbound responses. It captures TCP packets at the kernel level, extracts FIX Tag 11 (ClOrdID), matches request-response pairs, and computes in-out latency with nanosecond precision.

## Key Features

* **Kernel-level packet capture** using TC (Traffic Control) eBPF hooks on ingress/egress
* **Zero-copy ring buffers** for efficient kernel-to-userspace communication
* **FIX protocol parser** that extracts Tag 11 from TCP payloads using tail calls
* **Dual histogram tracking**:
  - Interval stats (MIN/AVG/MAX) reset every report period
  - Cumulative histogram for long-term percentile analysis (p50, p90, p99, p99.9, p99.99, p99.999)
* **HDR histogram** with 100ns resolution covering 0-10ms range
* **TCP port filtering** (bidirectional)
* **VLAN support** (802.1Q and 802.1ad)
* **Interactive keyboard controls** for on-demand histogram dumps
* **BPF CO-RE** (Compile Once, Run Everywhere) for portability across kernel versions
* **SKB linearization** to handle fragmented packets on egress

---

## Build

### Prerequisites
```bash
# Ubuntu/Debian
sudo apt install -y clang llvm libbpf-dev libelf-dev bpftool

# Amazon Linux / RHEL
sudo dnf install -y clang llvm libbpf-devel kernel-devel bpftool
```

### Compile
```bash
make
```

### Build Static Binary (for distribution)
```bash
make static
# Produces user/ebpf-fix-latency-tool-static (2.2MB, no runtime dependencies)

make dist
# Produces ebpf-fix-latency-tool-0.0.1.zip (versioned distribution package)
```

---

## Usage

### Basic Example
```bash
sudo ./user/ebpf-fix-latency-tool -i wlp0s20f3 -p 8080 -r 5
```

**Options:**
- `-i <interface>` : Network interface to monitor (required)
- `-p <port|range>` : TCP port or range to filter (e.g., `8080` or `12001-12010`, `0` = all ports, default: 0)
- `-r <seconds>` : Stats reporting interval (default: 5)
- `-m <max>` : Maximum concurrent pending requests (default: 65536)
- `-t <seconds>` : Request timeout in seconds (default: 0.5)
- `-v` : Show version and exit

**Port filtering examples:**
```bash
# Single port
sudo ./user/ebpf-fix-latency-tool -i eth0 -p 8080

# Port range (12001-12010)
sudo ./user/ebpf-fix-latency-tool -i eth0 -p 12001-12010

# All ports (no filtering)
sudo ./user/ebpf-fix-latency-tool -i eth0 -p 0
# or simply omit -p flag
sudo ./user/ebpf-fix-latency-tool -i eth0
```

### Sample Output

**Single port:**
```
sudo ./user/ebpf-fix-latency-tool -i wlp0s20f3 -p 8080 -r 5
ebpf-fix-latency-tool v0.0.1: attached to wlp0s20f3 (port=8080), reporting every 5s
Interval stats: MIN/AVG/MAX | Press '?' for keyboard commands
[fixlat] matched=325 inbound=325 outbound=325 mismatch=0 | rate: 78 match/sec | latency: min=24.250us avg=64.217us max=165.150us
[traffic] hooks: ingress=326 egress=325 | scanned: ingress=325 egress=325
[fixlat] matched=390 inbound=715 outbound=715 mismatch=0 | rate: 78 match/sec | latency: min=23.850us avg=63.961us max=203.950us
[traffic] hooks: ingress=765 egress=716 | scanned: ingress=715 egress=715 | filters: payload_zero=2 payload_small=0
[fixlat] matched=393 inbound=1108 outbound=1108 mismatch=0 | rate: 79 match/sec | latency: min=23.250us avg=43.723us max=197.750us
[traffic] hooks: ingress=1166 egress=1109 | scanned: ingress=1108 egress=1108 | filters: payload_zero=2 payload_small=0
```

**Port range:**
```
sudo ./user/ebpf-fix-latency-tool -i eth0 -p 12001-12010 -r 5
ebpf-fix-latency-tool v0.0.1: attached to eth0 (port=12001-12010), reporting every 5s
Interval stats: MIN/AVG/MAX | Press '?' for keyboard commands
[fixlat] matched=412 inbound=412 outbound=412 mismatch=0 | rate: 82 match/sec | latency: min=18.350us avg=52.100us max=124.850us
[traffic] hooks: ingress=413 egress=412 | scanned: ingress=412 egress=412
```

### Keyboard Controls

While running, press:
- **SPACE** - Dump detailed cumulative histogram
- **r** - Reset cumulative histogram
- **ESC** - Exit program
- **?** or any other key - Show help

**Example cumulative histogram dump:**
```
========== CUMULATIVE HISTOGRAM (all-time, n=1384) ==========
MIN:      23.250us
AVG:      56.740us
P50:      62.150us
P90:      67.850us
P99:      103.650us
P99.9:    175.250us
P99.99:   197.750us
P99.999:  197.750us
MAX:      203.950us
==============================================================
```

---

## Output Explained

### Interval Stats (printed every N seconds)
```
[fixlat] matched=325 inbound=325 outbound=325 mismatch=0 | rate: 78 match/sec | latency: min=24.250us avg=64.217us max=165.150us
```
- **matched**: Number of request-response pairs correlated during interval
- **inbound**: Total Tag 11 values extracted from ingress packets (all-time)
- **outbound**: Total Tag 11 values extracted from egress packets (all-time)
- **mismatch**: Egress Tag 11 values with no matching ingress request (all-time)
- **rate**: Matches per second during interval
- **latency**: MIN/AVG/MAX latency for matched pairs during interval (resets each report)

### Traffic Stats
```
[traffic] hooks: ingress=326 egress=325 | scanned: ingress=325 egress=325 | filters: payload_zero=2 payload_small=0 | fragmented: ingress=0 egress=145
```
- **hooks**: TC hook invocations (all-time)
- **scanned**: Packets that passed filters and started payload scanning (all-time)
- **filters**: Packets dropped by filters (empty payload, too small)
- **fragmented**: Non-linear packets that required linearization (only shown if non-zero). Common on egress (GSO), rare on ingress (GRO).

### Error Stats (only shown if non-zero)
```
[ERRORS] cb_clobbered=0 tag11_too_long=0 parser_stuck=0
```
- **cb_clobbered**: SKB control buffer corrupted between tail calls
- **tag11_too_long**: Tag 11 value exceeded 24 bytes
- **parser_stuck**: Tail call scanner made no forward progress

### Pending Map Health (shown if evictions occur or approaching limit)
```
[pending] active=1234/65536 stale_evicted=15 forced=0
```
- **active**: Current number of pending requests / maximum allowed
- **stale_evicted**: Requests evicted due to timeout (TTL expired)
- **forced**: Requests evicted to make room when at limit (should be rare)

---



### Test Traffic Generator
```bash
# Terminal 1: Start FIX server
./test-load/server.py 127.0.0.1 8080

# Terminal 2: Start client
./test-load/client.py 127.0.0.1 8080

# Terminal 3: Monitor latency
sudo ./user/ebpf-fix-latency-tool -i lo -p 8080 -r 5
```

---

## Distribution

See [DISTRIBUTION.md](DISTRIBUTION.md) for deployment options including:
- Source distribution
- Static binary distribution (recommended for production)
- Amazon Linux 2023 / cloud deployment
- Systemd service setup

**Quick deployment:**
```bash
# Build distribution package
make dist

# Copy to target server (no dependencies needed!)
scp ebpf-fix-latency-tool-0.0.1.zip user@server:/tmp/

# On target server
unzip /tmp/ebpf-fix-latency-tool-0.0.1.zip
sudo cp ebpf-fix-latency-tool-0.0.1/ebpf-fix-latency-tool /usr/local/bin/

# Run
sudo /usr/local/bin/ebpf-fix-latency-tool -i eth0 -p 8080 -r 5
```

---

## Kernel Requirements

- Linux kernel 5.10+ (tested on 6.1+)
- BPF support (CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y)
- TC support (CONFIG_NET_CLS_BPF=y, CONFIG_NET_SCH_INGRESS=y)
- BPF JIT (CONFIG_BPF_JIT=y)

All features are enabled by default on modern distributions (Ubuntu 22.04+, Amazon Linux 2023, etc.)

---

## Cleanup

Remove TC hooks when done:
```bash
sudo tc qdisc del dev <interface> clsact 2>/dev/null || true
```

The program automatically cleans up on exit (Ctrl+C or ESC key).

---

## Technical Details

### FIX Protocol Support
- Searches for Tag 11 pattern: `\x01 11=<value>\x01`
- Supports Tag 11 values up to 24 bytes
- No FIX version restrictions (searches raw TCP payload)
- Tag 11 must be complete within a single TCP packet (see Limitations)

### Performance
- **Overhead**: ~1-2% CPU at 100k msg/sec
- **Latency impact**: <1μs (kernel-level capture)
- **Memory**: ~3MB (ring buffers + histograms + hash table)
- **Scalability**: Per-CPU maps for lock-free stats

### Limitations
- **Tag 11 correlation only**: The tool uses FIX Tag 11 (ClOrdID) exclusively for correlating inbound requests with outbound responses. Other FIX tags (e.g., Tag 37 OrderID, Tag 41 OrigClOrdID) are not supported for correlation.
- **Fragmented FIX messages**: Partially supported. If a Tag 11 field is split across TCP packets (e.g., `\x01 11=` in one packet, `ORDER123\x01` in the next), the parser will miss it. Tag 11 must be complete within a single TCP packet.
- **Non-linear SKBs (GRO/LRO)**: The tool automatically detects and linearizes fragmented packets on both ingress and egress. Fragmentation is rare on ingress (occurs with GRO/Large Receive Offload enabled) but common on egress (GSO/Generic Segmentation Offload). Fragmentation events are tracked in the `fragmented` counter. If high fragmentation is observed on ingress, this may indicate GRO is enabled on the interface.
- **Request-response model**: Expects at least one response message for each inbound request. Multiple responses per request are not explicitly handled.
- **Max packet size**: 1500 bytes (no jumbo frame support)
- **Max Tag 11 scanning depth**: 1280 bytes per packet (256 bytes × 5 tail call stages)
- **Tag 11 value length**: Maximum 24 bytes (FIXLAT_MAX_TAGVAL_LEN)
- **Concurrent pending requests**: Maximum 65,536 unique Tag 11 values awaiting responses at any given moment (configurable via `-m`). Stale entries are automatically evicted after 500ms timeout (configurable via `-t`). When at limit, oldest entries are evicted to make room.
- **Single Tag 11 per message**: Assumes Tag 11 appears exactly once per FIX message
- **IPv4 only**: No IPv6 support
- **TCP only**: UDP-based protocols not supported
- **No persistence**: Pending requests are lost if the tool crashes or exits

---

## License

GPL (required for eBPF programs)

---

## Troubleshooting

### "eBPF not available" or permission errors
**Cause**: Tool was run without sudo/root privileges.

**Solution**: eBPF programs require CAP_BPF or root privileges. Always run with sudo:
```bash
sudo ./user/ebpf-fix-latency-tool -i eth0 -p 8080 -r 5
```

### "Exclusivity flag on, cannot modify" errors on startup
Harmless. TC clsact qdisc already exists on interface. The program continues successfully.

### No matches shown but traffic exists
- Check port filter
- Verify FIX protocol: Must have Tag 11 in both request and response
- Check payload size: Minimum 32 bytes required

### High mismatch count
- Request-response not correlated (different Tag 11 values)
- Responses arriving before requests captured (tool started mid-stream)
- Hash table overflow at very high rates

### Parser errors (cb_clobbered, parser_stuck)
Contact maintainer with kernel version and traffic characteristics.
