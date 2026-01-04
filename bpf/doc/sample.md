Sample run

AL2, around 280K messages/sec:


```
[ec2-user@ip-10-0-2-147 ebpf-fix-latency-tool-0.0.5]$ sudo ./ebpf-fix-latency-tool -i eth0 -p 12001 -c 5 -r 5
libbpf: Kernel error message: Exclusivity flag on, cannot modify
libbpf: Kernel error message: Exclusivity flag on, cannot modify
ebpf-fix-latency-tool v0.0.5 | eth0:12001 | tracking up to 16k pending tags (256K RAM) | histogram 0-100ms (85K RAM)
Userspace thread pinned to CPU core 5
Interval stats: MIN/AVG/MAX (5s intervals) | Press '?' for keyboard commands
[traffic] hooks: ingress=748804 egress=742864 | scanned: ingress=14998 egress=14880 | filters: payload_zero=93 payload_small=2 | fragmented: ingress=0 egress=14880
[fixlat] matched=14879 inbound=14998 outbound=14880 mismatch=0 | rate: 3661 match/sec | latency: min=12.849us avg=24.105us max=62.849us
[pending] active=0/16384 stale_evicted=118 forced=0
[traffic] hooks: ingress=1662788 egress=1656705 | scanned: ingress=33315 egress=33197 | filters: payload_zero=291 payload_small=3 | fragmented: ingress=0 egress=33197
[fixlat] matched=18317 inbound=33315 outbound=33197 mismatch=0 | rate: 3663 match/sec | latency: min=12.849us avg=24.073us max=87.549us
[pending] active=1/16384 stale_evicted=118 forced=0
[traffic] hooks: ingress=2576775 egress=2570257 | scanned: ingress=51616 egress=51498 | filters: payload_zero=902 payload_small=4 | fragmented: ingress=0 egress=51498
[fixlat] matched=18302 inbound=51616 outbound=51498 mismatch=0 | rate: 3660 match/sec | latency: min=12.849us avg=25.353us max=487.499us
[pending] active=0/16384 stale_evicted=118 forced=0
[traffic] hooks: ingress=3490528 egress=3483887 | scanned: ingress=69918 egress=69803 | filters: payload_zero=1053 payload_small=5 | fragmented: ingress=0 egress=69803
[fixlat] matched=18302 inbound=69918 outbound=69803 mismatch=3 | rate: 3660 match/sec | latency: min=12.949us avg=23.990us max=135.499us
[pending] active=0/16384 stale_evicted=118 forced=0
[traffic] hooks: ingress=4404577 egress=4397800 | scanned: ingress=88230 egress=88116 | filters: payload_zero=1224 payload_small=6 | fragmented: ingress=0 egress=88116
[fixlat] matched=18312 inbound=88230 outbound=88116 mismatch=1 | rate: 3662 match/sec | latency: min=12.149us avg=24.227us max=69.449us
[pending] active=0/16384 stale_evicted=118 forced=0
[traffic] hooks: ingress=5318424 egress=5311534 | scanned: ingress=106528 egress=106418 | filters: payload_zero=1366 payload_small=7 | fragmented: ingress=0 egress=106418
[fixlat] matched=18298 inbound=106528 outbound=106418 mismatch=4 | rate: 3660 match/sec | latency: min=12.749us avg=24.555us max=80.949us
[pending] active=0/16384 stale_evicted=118 forced=0
[traffic] hooks: ingress=6232196 egress=6225181 | scanned: ingress=124829 egress=124719 | filters: payload_zero=1527 payload_small=8 | fragmented: ingress=0 egress=124719
[fixlat] matched=18301 inbound=124829 outbound=124719 mismatch=0 | rate: 3660 match/sec | latency: min=12.949us avg=24.681us max=94.549us
[pending] active=0/16384 stale_evicted=118 forced=0
[traffic] hooks: ingress=7145824 egress=7138648 | scanned: ingress=143135 egress=143025 | filters: payload_zero=1712 payload_small=9 | fragmented: ingress=0 egress=143025
[fixlat] matched=18306 inbound=143135 outbound=143025 mismatch=0 | rate: 3661 match/sec | latency: min=12.949us avg=24.717us max=77.949us
[pending] active=0/16384 stale_evicted=118 forced=0
[traffic] hooks: ingress=8059418 egress=8052084 | scanned: ingress=161432 egress=161322 | filters: payload_zero=1910 payload_small=10 | fragmented: ingress=0 egress=161322
[fixlat] matched=18297 inbound=161432 outbound=161322 mismatch=0 | rate: 3659 match/sec | latency: min=12.449us avg=24.970us max=93.249us
[pending] active=0/16384 stale_evicted=118 forced=0
[traffic] hooks: ingress=8973580 egress=8966006 | scanned: ingress=179739 egress=179629 | filters: payload_zero=2209 payload_small=11 | fragmented: ingress=0 egress=179629
[fixlat] matched=18307 inbound=179739 outbound=179629 mismatch=0 | rate: 3661 match/sec | latency: min=13.249us avg=25.185us max=402.499us
[pending] active=0/16384 stale_evicted=118 forced=0
[traffic] hooks: ingress=9887432 egress=9879106 | scanned: ingress=198021 egress=197911 | filters: payload_zero=3041 payload_small=12 | fragmented: ingress=0 egress=197911
[fixlat] matched=18282 inbound=198021 outbound=197911 mismatch=0 | rate: 3656 match/sec | latency: min=12.749us avg=25.149us max=202.499us
[pending] active=0/16384 stale_evicted=118 forced=0
[traffic] hooks: ingress=10801369 egress=10792895 | scanned: ingress=216299 egress=216189 | filters: payload_zero=3222 payload_small=13 | fragmented: ingress=0 egress=216189
[fixlat] matched=18278 inbound=216299 outbound=216189 mismatch=0 | rate: 3656 match/sec | latency: min=12.949us avg=24.476us max=90.949us
[pending] active=0/16384 stale_evicted=118 forced=0
[traffic] hooks: ingress=11715419 egress=11706797 | scanned: ingress=234595 egress=234485 | filters: payload_zero=3403 payload_small=14 | fragmented: ingress=0 egress=234485
[fixlat] matched=18296 inbound=234595 outbound=234485 mismatch=0 | rate: 3659 match/sec | latency: min=12.649us avg=24.660us max=116.499us
[pending] active=0/16384 stale_evicted=118 forced=0

========== CUMULATIVE HISTOGRAM (all-time, n=238774) ==========
MIN:      12.149us
AVG:      24.636us
P50:      23.449us
P90:      33.549us
P99:      45.049us
P99.9:    59.249us
P99.99:   203.499us
P99.999:  356.499us
MAX:      487.499us

Distribution:
  12.1us-17.0us |################ 24861 (10.4%)
  17.1us-22.0us |################################################## 73992 (31.0%)
  22.1us-27.0us |############################################# 67713 (28.4%)
  27.1us-32.0us |########################### 41146 (17.2%)
  32.1us-37.0us |############ 19043 (8.0%)
  37.1us-42.0us |##### 7650 (3.2%)
  42.1us-47.0us |# 2830 (1.2%)
  47.1us-52.0us | 941 (0.4%)
  52.1us-57.0us | 304 (0.1%)
  57.1us-62.0us | 115 (0.0%)
  62.1us-67.0us | 54 (0.0%)
  67.1us-72.0us | 29 (0.0%)
  72.1us-77.0us | 10 (0.0%)
  77.1us-82.0us | 8 (0.0%)
  82.1us-87.0us | 8 (0.0%)
  87.1us-92.0us | 10 (0.0%)
  92.1us-97.0us | 4 (0.0%)
 97.1us-120.5us | 6 (0.0%)
121.5us-170.5us | 9 (0.0%)
171.5us-220.5us | 22 (0.0%)
221.5us-270.5us | 6 (0.0%)
271.5us-320.5us | 6 (0.0%)
321.5us-370.5us | 4 (0.0%)
371.5us-420.5us | 1 (0.0%)
421.5us-470.5us | 1 (0.0%)
471.5us-487.5us | 1 (0.0%)
==============================================================

```