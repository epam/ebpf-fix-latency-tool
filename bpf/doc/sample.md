Sample run

AL2, around 280K messages/sec:


```
[ec2-user@ip-10-0-2-70 ebpf-fix-latency-tool-0.0.3]$ sudo ./ebpf-fix-latency-tool -i eth0 -p 12001-12050 -c 5
libbpf: Kernel error message: Exclusivity flag on, cannot modify
libbpf: Kernel error message: Exclusivity flag on, cannot modify
ebpf-fix-latency-tool v0.0.3: attached to eth0 (port=12001-12050), reporting every 5s
Userspace thread pinned to CPU core 5
Interval stats: MIN/AVG/MAX | Press '?' for keyboard commands
[fixlat] matched=641250 inbound=644655 outbound=641311 mismatch=11 | rate: 139528 match/sec | latency: min=50ns avg=31.808us max=9999.950us
[traffic] hooks: ingress=644794 egress=641331 | scanned: ingress=644655 egress=641311 | filters: payload_zero=137 payload_small=2 | fragmented: ingress=0 egress=641311
[pending] active=4/65536 stale_evicted=3350 forced=0
[fixlat] matched=697519 inbound=1342167 outbound=1338838 mismatch=12 | rate: 139504 match/sec | latency: min=50ns avg=33.863us max=9999.950us
[traffic] hooks: ingress=1342442 egress=1338877 | scanned: ingress=1342167 egress=1338838 | filters: payload_zero=267 payload_small=3 | fragmented: ingress=0 egress=1338838
[pending] active=7/65536 stale_evicted=3350 forced=0
...
[fixlat] matched=697510 inbound=127597796 outbound=127597516 mismatch=13 | rate: 139502 match/sec | latency: min=50ns avg=33.216us max=9999.950us
[traffic] hooks: ingress=127619186 egress=127601932 | scanned: ingress=127597343 egress=127596351 | filters: payload_zero=21726 payload_small=209 | fragmented: ingress=40 egress=127596351
[pending] active=4/65536 stale_evicted=4612 forced=0

========== CUMULATIVE HISTOGRAM (all-time, n=128182644) ==========
MIN:      50ns
AVG:      32.872us
P50:      29.450us
P90:      52.750us
P99:      174.550us
P99.9:    9999.950us
P99.99:   9999.950us
P99.999:  9999.950us
MAX:      9999.950us
==============================================================
```