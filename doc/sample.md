## Sample runs



AL2023, sustained load of around 180K messages/sec:


```
[ec2-user@ip-10-0-2-198 ebpf-fix-latency-tool-0.0.9]$ sudo ./ebpf-fix-latency-tool -i ens5 -p 12001-12050 -r 5 -c 5 -s spin
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

[reset] Cumulative histogram cleared

...

[fixlat] matched=914195 inbound=499494588 outbound=499504436 mismatch=16 dup_ingress=0 negative=0 | rate: 182839 match/sec | latency: min=52.483us avg=303.887us max=850.319us
[pending] active=60/16384 stale_evicted=1176 forced=0
[traffic] hooks: ingress=555204150 egress=515741113 | scanned: ingress=500408053 egress=500411195 | filters: payload_zero=70101343 payload_small=705 | fragmented: ingress=77 egress=500411195
[fixlat] matched=914287 inbound=500408875 outbound=500418742 mismatch=16 dup_ingress=0 negative=0 | rate: 182857 match/sec | latency: min=53.282us avg=303.243us max=800.645us
[pending] active=60/16384 stale_evicted=1176 forced=0
[traffic] hooks: ingress=556213880 egress=516684608 | scanned: ingress=501322316 egress=501325480 | filters: payload_zero=70225988 payload_small=706 | fragmented: ingress=77 egress=501325480
[fixlat] matched=914269 inbound=501323138 outbound=501333027 mismatch=17 dup_ingress=0 negative=0 | rate: 182854 match/sec | latency: min=52.728us avg=302.804us max=799.166us
[pending] active=54/16384 stale_evicted=1176 forced=0

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


AL2, 500K msg/sec:

```
[fixlat] matched=1138606 inbound=8050630786 outbound=8050689489 mismatch=18 dup_ingress=0 negative=0 | rate: 227721 match/sec | latency: min=112.038us avg=691.042us max=1481.339us
[pending] active=165/16384 stale_evicted=84187 forced=20911
[traffic] hooks: ingress=10384898495 egress=7997265388 | scanned: ingress=8051767299 egress=6882993813 | filters: payload_zero=3447171221 payload_small=8031 | fragmented: ingress=74 egress=6882993813
[fixlat] matched=1138405 inbound=8051769248 outbound=8051827906 mismatch=15 dup_ingress=0 negative=0 | rate: 227681 match/sec | latency: min=107.233us avg=737.781us max=6575.788us
[pending] active=145/16384 stale_evicted=84262 forced=20911
[traffic] hooks: ingress=10386361963 egress=7998384118 | scanned: ingress=8052905445 egress=6883960351 | filters: payload_zero=3447648705 payload_small=8032 | fragmented: ingress=74 egress=6883960351
[fixlat] matched=1138142 inbound=8052907394 outbound=8052966068 mismatch=20 dup_ingress=0 negative=0 | rate: 227628 match/sec | latency: min=104.864us avg=686.261us max=1555.118us
[pending] active=152/16384 stale_evicted=84262 forced=20911
[traffic] hooks: ingress=10387825634 egress=7999503662 | scanned: ingress=8054043628 egress=6884927471 | filters: payload_zero=3448126596 payload_small=8033 | fragmented: ingress=74 egress=6884927471
[fixlat] matched=1138159 inbound=8054045577 outbound=8054104237 mismatch=7 dup_ingress=0 negative=0 | rate: 227632 match/sec | latency: min=96.493us avg=685.797us max=3306.606us
[pending] active=148/16384 stale_evicted=84293 forced=20911
[traffic] hooks: ingress=10389288790 egress=8000623457 | scanned: ingress=8055181193 egress=6885894942 | filters: payload_zero=3448604482 payload_small=8034 | fragmented: ingress=74 egress=6885894942
[fixlat] matched=1137542 inbound=8055183142 outbound=8055241790 mismatch=14 dup_ingress=0 negative=0 | rate: 227508 match/sec | latency: min=110.553us avg=684.313us max=1415.920us
[pending] active=169/16384 stale_evicted=84293 forced=20911
[traffic] hooks: ingress=10390752149 egress=8001742849 | scanned: ingress=8056319181 egress=6886862313 | filters: payload_zero=3449081855 payload_small=8035 | fragmented: ingress=74 egress=6886862313
[fixlat] matched=1137987 inbound=8056321130 outbound=8056379789 mismatch=8 dup_ingress=0 negative=0 | rate: 227597 match/sec | latency: min=102.240us avg=685.129us max=1461.786us
[pending] active=165/16384 stale_evicted=84293 forced=20911
[traffic] hooks: ingress=10392213577 egress=8002860285 | scanned: ingress=8057457442 egress=6887827861 | filters: payload_zero=3449556887 payload_small=8036 | fragmented: ingress=74 egress=6887827861
[fixlat] matched=1138274 inbound=8057459391 outbound=8057518072 mismatch=13 dup_ingress=0 negative=0 | rate: 227655 match/sec | latency: min=108.327us avg=690.045us max=1585.924us
[pending] active=155/16384 stale_evicted=84293 forced=20911
[traffic] hooks: ingress=10393676812 egress=8003978862 | scanned: ingress=8058595957 egress=6888793979 | filters: payload_zero=3450034040 payload_small=8037 | fragmented: ingress=74 egress=6888793980
[fixlat] matched=1138516 inbound=8058597906 outbound=8058656604 mismatch=14 dup_ingress=0 negative=0 | rate: 227703 match/sec | latency: min=106.706us avg=686.986us max=1571.297us
[pending] active=155/16384 stale_evicted=84293 forced=20911
[traffic] hooks: ingress=10395139635 egress=8005096964 | scanned: ingress=8059733872 egress=6889759593 | filters: payload_zero=3450511396 payload_small=8038 | fragmented: ingress=74 egress=6889759593
[fixlat] matched=1137918 inbound=8059735821 outbound=8059794558 mismatch=36 dup_ingress=0 negative=0 | rate: 227584 match/sec | latency: min=106.980us avg=686.612us max=1686.505us
[pending] active=153/16384 stale_evicted=84293 forced=20911
[traffic] hooks: ingress=10396604263 egress=8006216937 | scanned: ingress=8060872546 egress=6890727157 | filters: payload_zero=3450989723 payload_small=8039 | fragmented: ingress=74 egress=6890727157
[fixlat] matched=1138659 inbound=8060874495 outbound=8060933245 mismatch=28 dup_ingress=0 negative=0 | rate: 227732 match/sec | latency: min=103.969us avg=685.257us max=1588.953us
[pending] active=169/16384 stale_evicted=84293 forced=20911

========== CUMULATIVE HISTOGRAM (all-time, n=8058905613) ==========
MIN:      17.049us
P50:      638.499us
P90:      1004.999us
P99:      1214.999us
P99.9:    1474.999us
P99.99:   6364.999us
P99.999:  45249.999us
MAX:      100000.000us

Distribution:
   17.0us-31.0us | 90 (0.0%)
   31.1us-45.1us | 286 (0.0%)
   45.2us-59.2us | 590 (0.0%)
   59.3us-73.3us | 1202 (0.0%)
   73.4us-87.4us | 2161 (0.0%)
  87.5us-115.5us | 87157 (0.0%)
 116.5us-256.5us |### 183162377 (2.3%)
 257.5us-397.5us |############# 681527406 (8.5%)
 398.5us-538.5us |####################### 1207151684 (15.0%)
 539.5us-679.5us |################################################## 2533807555 (31.4%)
 680.5us-820.5us |########################### 1403234735 (17.4%)
 821.5us-961.5us |################### 993300038 (12.3%)
  962.5us-2.02ms |#################### 1052315590 (13.1%)
   2.03ms-3.43ms | 1550854 (0.0%)
   3.44ms-4.84ms | 1161663 (0.0%)
   4.85ms-6.25ms | 763255 (0.0%)
   6.26ms-7.66ms | 284950 (0.0%)
   7.67ms-9.07ms | 87219 (0.0%)
  9.08ms-14.85ms | 177815 (0.0%)
 14.95ms-28.95ms | 124739 (0.0%)
 29.05ms-43.05ms | 75619 (0.0%)
 43.15ms-57.15ms | 40162 (0.0%)
 57.25ms-71.25ms | 47389 (0.0%)
 71.35ms-85.35ms | 1074 (0.0%)
99.55ms-100.00ms | 3 (0.0%)
==============================================================
```






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
