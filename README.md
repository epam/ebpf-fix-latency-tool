# ebpf-fix-latency-tool - eBPF FIX Protocol Latency Monitor

[![CI](https://github.com/epam/ebpf-fix-latency-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/epam/ebpf-fix-latency-tool/actions/workflows/ci.yml)

**Latency measurement tool for FIX protocol traffic using eBPF TC hooks**

`ebpf-fix-latency-tool` is a lightweight eBPF-based tool that measures roundtrip latency for FIX protocol messages by correlating inbound requests with outbound responses. 

![Design](doc/design-diagram.png)

It captures TCP packets at the kernel level, extracts all occurences of FIX Tag 11 (ClOrdID) and send them together with monotonic timestamp to user space thread. User space thread matches request-response pairs, and computes in-out latency with nanosecond precision. Latencies are collected into HDR histogram. For outbound packets only the first occurence of each FIX tag 11 is processed (assuming first message to contain ACK/NAC for each order request).

![Outbound to inbound packet correlation](doc/inbound-outbound-correlation.png)


## Key Features

* **Kernel-level packet capture** using TC (Traffic Control) eBPF hooks on ingress/egress
* **FIX protocol parser** that extracts Tag 11 from TCP payloads using tail calls
* **Interval stats** (MIN/AVG/MAX) reset every report period
* **Cumulative histogram** for long-term percentile analysis (p50, p90, p99, p99.9, p99.99, p99.999)
* **HDR histogram** with 3 significant figures precision (configurable 0-100ms range by default)
* **ASCII histogram visualization** for visual distribution analysis

### Tested on

eBPF logic is sensitive to verifier constraints (design and tag 11 parsing algorithm heavily influenced by eBPF verifier limitations). The tool was tested on:

* Ubuntu 24.04.3 LTS (kernel 6.14.0-37-generic)
* Amazon Linux 2 (kernel 5.10.205)
* Amazon Linux 2023 (kernel 6.12.58-82.121.amzn2023.x86_64)


---

## Quick Start

### Step 1: Download and Extract

```bash
# Download latest release and extact it
wget https://github.com/epam/ebpf-fix-latency-tool/releases/latest/download/ebpf-fix-latency-tool-0.0.8.zip
unzip ebpf-fix-latency-tool-0.0.8.zip
cd ebpf-fix-latency-tool-0.0.8/
```


### Step 2: Basic Example

Monitor FIX traffic on interface eth0, port 8080, with 5-second reporting intervals:
```bash
sudo ./ebpf-fix-latency-tool -i eth0 -p 8080 -r 5
```

### Command-Line Options
- `-i <interface>` : Network interface to monitor (required)
- `-p <port|range>` : TCP port or range to filter (e.g., `8080` or `12001-12010`) (required)
- `-r <seconds>` : Stats reporting interval (default: 5)
- `-m <max>` : Maximum concurrent pending requests (default: 16384)
- `-t <seconds>` : Request timeout in seconds (default: 0.5)
- `-c <cpu>` : Pin userspace thread to specific CPU core for consistent measurements (optional)
- `-s <strategy>` : Idle strategy - `spin` (busy-spin CPU) or `backoff` (progressive backoff, default)
- `-x <milliseconds>` : Maximum latency to track in histogram (default: 100ms)
- `-v` : Show version and exit

### Additional Examples

**Port range:**
```bash
# Monitor port range (12001-12010)
sudo ./ebpf-fix-latency-tool -i eth0 -p 12001-12010
```

**CPU pinning for lowest latency:**
```bash
# Pin userspace thread to CPU core 3
sudo ./ebpf-fix-latency-tool -i eth0 -p 8080 -c 3

# Pin to CPU core 3 with aggressive busy-spin idle strategy (minimum latency)
sudo ./ebpf-fix-latency-tool -i eth0 -p 8080 -c 3 -s spin
```

**Custom histogram range:**
```bash
# Track latencies up to 500ms (useful for high-latency environments)
sudo ./ebpf-fix-latency-tool -i eth0 -p 8080 -x 500
```

### Sample Output

**Production example with CPU pinning:**
```
sudo ./ebpf-fix-latency-tool -i ens5 -p 12001-12050 -r 5 -c 5 -s spin
libbpf: Kernel error message: Exclusivity flag on, cannot modify
ebpf-fix-latency-tool v0.0.9 | ens5:12001-12050 | tracking up to 16k pending tags (256K RAM) | histogram 0-100ms (42K RAM)
Userspace thread pinned to CPU core 5 | CPU spinning idle strategy selected
Interval stats: MIN/AVG/MAX (5s intervals) | Press '?' for keyboard commands
[traffic] hooks: ingress=1008951 egress=943689 | scanned: ingress=914673 egress=914613 | filters: payload_zero=123322 payload_small=1 | fragmented: ingress=0 egress=914613
[fixlat] matched=914574 inbound=914674 outbound=914624 mismatch=31 dup_ingress=0 negative=0 | rate: 182915 match/sec | latency: min=16.855us avg=303.022us max=1067.702us
[pending] active=53/16384 stale_evicted=30 forced=0
[traffic] hooks: ingress=2014412 egress=1887472 | scanned: ingress=1829437 egress=1829386 | filters: payload_zero=242992 payload_small=2 | fragmented: ingress=0 egress=1829386
[fixlat] matched=914773 inbound=1829438 outbound=1829397 mismatch=18 dup_ingress=0 negative=0 | rate: 182955 match/sec | latency: min=50.771us avg=301.013us max=837.998us
[pending] active=59/16384 stale_evicted=30 forced=0
[traffic] hooks: ingress=3023631 egress=2831566 | scanned: ingress=2744153 egress=2744134 | filters: payload_zero=366798 payload_small=3 | fragmented: ingress=0 egress=2744134
[fixlat] matched=914723 inbound=2744154 outbound=2744152 mismatch=32 dup_ingress=0 negative=0 | rate: 182945 match/sec | latency: min=52.868us avg=303.174us max=1026.541us
[pending] active=53/16384 stale_evicted=30 forced=0
...
```

### Keyboard Controls

While running, press:
- **SPACE** - Dump detailed cumulative histogram
- **r** - Reset cumulative histogram
- **ESC** - Exit program
- **?** or any other key - Show help

**Example cumulative histogram dump (press SPACE):**
```
========== CUMULATIVE HISTOGRAM (all-time, n=499196989) ==========
MIN:      13.449us
P50:      307.499us
P90:      443.499us
P99:      544.499us
P99.9:    607.499us
P99.99:   681.499us
P99.999:  1954.999us
MAX:      25749.999us

Distribution:
  13.4us-24.5us | 2261 (0.0%)
  24.6us-35.7us | 4774 (0.0%)
  35.8us-46.9us | 4567 (0.0%)
  47.0us-58.1us | 50660 (0.0%)
  58.2us-69.3us | 1061267 (0.2%)
  69.4us-80.5us | 2565529 (0.5%)
  80.6us-91.7us | 4060757 (0.8%)
 91.8us-129.5us |##### 21713919 (4.3%)
130.5us-241.5us |########################## 106901549 (21.4%)
242.5us-353.5us |################################################## 204238661 (40.9%)
354.5us-465.5us |############################### 127043452 (25.4%)
466.5us-577.5us |####### 29976209 (6.0%)
578.5us-689.5us | 1530390 (0.3%)
690.5us-801.5us | 23844 (0.0%)
802.5us-913.5us | 3835 (0.0%)
 914.5us-1.25ms | 4511 (0.0%)
  1.26ms-2.37ms | 8203 (0.0%)
  2.38ms-3.49ms | 1779 (0.0%)
  3.50ms-4.61ms | 733 (0.0%)
  4.62ms-5.73ms | 88 (0.0%)
23.45ms-25.75ms | 1 (0.0%)
==============================================================
```

---

## Output Explained

### Traffic Stats (printed first)
```
[traffic] hooks: ingress=748804 egress=742864 | scanned: ingress=14998 egress=14880 | filters: payload_zero=93 payload_small=2 | fragmented: ingress=0 egress=14880
```
- **hooks**: TC hook invocations (all-time cumulative)
- **scanned**: Packets that passed filters and started Tag 11 payload scanning (all-time cumulative)
- **filters**: Packets dropped by filters (empty payload or too small - minimum 32 bytes)
- **fragmented**: Non-linear packets that required linearization (only shown if non-zero). Common on egress (GSO), rare on ingress (GRO)

### Latency Stats (printed second)
```
[fixlat] matched=14879 inbound=14998 outbound=14880 mismatch=0 | rate: 3661 match/sec | latency: min=12.849us avg=24.105us max=62.849us
```
- **matched**: Number of request-response pairs correlated during this interval (resets each report)
- **inbound**: Total Tag 11 values extracted from ingress packets (all-time cumulative)
- **outbound**: Total Tag 11 values extracted from egress packets (all-time cumulative)
- **mismatch**: Egress Tag 11 values with no matching ingress request (all-time cumulative)
- **rate**: Matches per second during this interval
- **latency**: MIN/AVG/MAX latency for matched pairs during this interval (resets each report)

### Error Stats (only shown if non-zero)
```
[ERRORS] cb_clobbered=0 tag11_too_long=0 parser_stuck=0
```
- **cb_clobbered**: SKB control buffer corrupted between tail calls
- **tag11_too_long**: Tag 11 value exceeded 24 bytes
- **parser_stuck**: Tail call scanner made no forward progress

### Pending Map Health (printed third)
```
[pending] active=1/16384 stale_evicted=118 forced=0
```
- **active**: Current number of in-flight pending requests / maximum capacity
- **stale_evicted**: Requests evicted due to timeout (TTL expired) - cumulative count
- **forced**: Requests evicted via FIFO to make room when at capacity (should be rare) - cumulative count

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

**Note:** `bpf/vmlinux.h` is committed to the repository for CI compatibility (GitHub Actions lacks BTF support). To regenerate it from your local kernel:
```bash
make vmlinux-regenerate
```

### Build Static Binary (for distribution)
```bash
make static
# Produces user/ebpf-fix-latency-tool-static (2.3MB, no runtime dependencies)

make dist
# Produces ebpf-fix-latency-tool-VERSION.zip (versioned distribution package)
```
---

## Distribution

See [DISTRIBUTION.md](DISTRIBUTION.md) for deployment options including:
- Pre-built binaries from GitHub releases (recommended)
- Static binary distribution (no dependencies)
- Source distribution
- Amazon Linux / cloud deployment
- Systemd service setup

**Quick deployment from GitHub releases:**
```bash
# Download latest release
wget https://github.com/epam/ebpf-fix-latency-tool/releases/latest/download/ebpf-fix-latency-tool-static

# Install
sudo install -m 755 ebpf-fix-latency-tool-static /usr/local/bin/ebpf-fix-latency-tool

# Run
sudo ebpf-fix-latency-tool -i eth0 -p 8080 -r 5
```

**Or build distribution package locally:**
```bash
# Build and create ZIP
make dist

# Deploy (version number read from VERSION file)
scp ebpf-fix-latency-tool-*.zip user@server:/tmp/
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


### Limitations
- **Tag 11 correlation only**: The tool uses FIX Tag 11 (ClOrdID) exclusively for correlating inbound requests with outbound responses. Other FIX tags (e.g., Tag 37 OrderID, Tag 41 OrigClOrdID) are not supported for correlation.
- **Duplicate Tag 11 handling**: Userspace collection logic does not support duplicate inbound Tag 11 values. For outbound messages, only the first occurrence of a duplicate Tag 11 is processed. This works well for OMS systems that require unique order IDs (Tag 11) and may respond with multiple execution reports for each order (only the first response counts for order ack latency).
- **Fragmented FIX messages**: Partially supported. If a Tag 11 field is split across TCP packets (e.g., `\x01 11=` in one packet, `ORDER123\x01` in the next), the parser will miss it. Tag 11 must be complete within a single TCP packet.
- **Non-linear SKBs (GRO/LRO)**: The tool automatically detects and linearizes fragmented packets on both ingress and egress. Fragmentation is rare on ingress (occurs with GRO/Large Receive Offload enabled) but common on egress (GSO/Generic Segmentation Offload). Fragmentation events are tracked in the `fragmented` counter. If high fragmentation is observed on ingress, this may indicate GRO is enabled on the interface.
- **Request-response model**: Expects at least one response message for each inbound request. Multiple responses per request are not explicitly handled.
- **Max packet size**: 1500 bytes (no jumbo frame support)
- **Max Tag 11 scanning depth**: 1792 bytes per packet (256 bytes × 7 tail call stages)
- **Tag 11 value length**: Maximum 24 bytes (FIXLAT_MAX_TAGVAL_LEN)
- **Concurrent pending requests**: Maximum 16,384 unique Tag 11 values awaiting responses at any given moment (configurable via `-m`). Stale entries are automatically evicted after 500ms timeout (configurable via `-t`). When at limit, oldest entries are evicted to make room.
- **IPv4 only**: No IPv6 support
- **TCP only**: UDP-based protocols not supported
- **64-bit architecture only**: The tool is designed for 64-bit systems (x86_64, aarch64) due to the way per-CPU metrics are collected using non-atomic 64-bit increments.

---

## License

GPL (required for eBPF programs)

---

## Troubleshooting

### "Make sure your kernel supports BPF" or permission errors

```
libbpf: Error in bpf_object__probe_loading():Operation not permitted(1). Couldn't load trivial BPF program. Make sure your kernel supports BPF ```
```
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

### Parser errors (cb_clobbered, parser_stuck)
Contact the author with kernel version and traffic characteristics.
