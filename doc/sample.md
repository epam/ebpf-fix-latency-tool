Sample run

AL2023, around 2.5 K messages/sec:


```
[ec2-user@ip-10-0-2-13 ebpf-fix-latency-tool-0.0.7]$ sudo ./ebpf-fix-latency-tool -i ens5 -p 12001 -r 5 -c 5 -s spin
libbpf: Kernel error message: Exclusivity flag on, cannot modify
libbpf: Kernel error message: Exclusivity flag on, cannot modify
ebpf-fix-latency-tool v0.0.7 | ens5:12001 | tracking up to 16k pending tags (256K RAM) | histogram 0-100ms (42K RAM)
Userspace thread pinned to CPU core 5 | CPU spinning idle strategy selected
Interval stats: MIN/AVG/MAX (5s intervals) | Press '?' for keyboard commands
[traffic] hooks: ingress=134812 egress=140963 | scanned: ingress=10902 egress=14170 | filters: payload_zero=25796 payload_small=1 | fragmented: ingress=0 egress=14170
[fixlat] matched=10902 inbound=10902 outbound=14239 mismatch=3337 | rate: 2592 match/sec | latency: min=12.610us avg=14.884us max=57.721us
[traffic] hooks: ingress=294699 egress=307999 | scanned: ingress=23853 egress=30708 | filters: payload_zero=56190 payload_small=2 | fragmented: ingress=0 egress=30708
[fixlat] matched=12950 inbound=23853 outbound=30863 mismatch=3673 | rate: 2590 match/sec | latency: min=12.581us avg=14.785us max=49.627us
[traffic] hooks: ingress=455248 egress=475949 | scanned: ingress=36810 egress=47500 | filters: payload_zero=87176 payload_small=3 | fragmented: ingress=0 egress=47500
[fixlat] matched=12958 inbound=36810 outbound=47733 mismatch=3913 | rate: 2592 match/sec | latency: min=12.629us avg=14.902us max=56.118us
[traffic] hooks: ingress=615752 egress=643746 | scanned: ingress=49782 egress=64203 | filters: payload_zero=117965 payload_small=4 | fragmented: ingress=0 egress=64203
[fixlat] matched=12972 inbound=49782 outbound=64533 mismatch=3828 | rate: 2594 match/sec | latency: min=12.517us avg=14.881us max=52.847us
[traffic] hooks: ingress=775833 egress=811128 | scanned: ingress=62752 egress=80916 | filters: payload_zero=148359 payload_small=5 | fragmented: ingress=0 egress=80916
[fixlat] matched=12970 inbound=62752 outbound=81322 mismatch=3819 | rate: 2594 match/sec | latency: min=12.284us avg=14.881us max=60.071us
[traffic] hooks: ingress=936112 egress=978768 | scanned: ingress=75720 egress=97685 | filters: payload_zero=178964 payload_small=6 | fragmented: ingress=0 egress=97685
[fixlat] matched=12968 inbound=75720 outbound=98165 mismatch=3875 | rate: 2594 match/sec | latency: min=12.551us avg=14.928us max=80.611us
[traffic] hooks: ingress=1096366 egress=1146354 | scanned: ingress=88675 egress=114543 | filters: payload_zero=209693 payload_small=7 | fragmented: ingress=0 egress=114543
[fixlat] matched=12955 inbound=88675 outbound=115116 mismatch=3996 | rate: 2591 match/sec | latency: min=12.645us avg=15.282us max=500.876us
[traffic] hooks: ingress=1256435 egress=1313638 | scanned: ingress=101628 egress=131299 | filters: payload_zero=240232 payload_small=8 | fragmented: ingress=0 egress=131299
[fixlat] matched=12953 inbound=101628 outbound=131960 mismatch=3891 | rate: 2591 match/sec | latency: min=12.509us avg=15.046us max=58.002us
[traffic] hooks: ingress=1416808 egress=1481305 | scanned: ingress=114588 egress=148129 | filters: payload_zero=271017 payload_small=9 | fragmented: ingress=0 egress=148129
[fixlat] matched=12960 inbound=114588 outbound=148871 mismatch=3951 | rate: 2592 match/sec | latency: min=12.453us avg=14.954us max=64.925us
[traffic] hooks: ingress=1577048 egress=1648794 | scanned: ingress=127560 egress=164941 | filters: payload_zero=301548 payload_small=10 | fragmented: ingress=0 egress=164941
[fixlat] matched=12972 inbound=127560 outbound=165768 mismatch=3925 | rate: 2594 match/sec | latency: min=12.398us avg=14.913us max=49.558us
[traffic] hooks: ingress=1737048 egress=1816193 | scanned: ingress=140518 egress=181863 | filters: payload_zero=331972 payload_small=11 | fragmented: ingress=0 egress=181863
[fixlat] matched=12958 inbound=140518 outbound=182762 mismatch=4036 | rate: 2592 match/sec | latency: min=12.076us avg=15.019us max=73.655us
[traffic] hooks: ingress=1897257 egress=1983763 | scanned: ingress=153479 egress=198631 | filters: payload_zero=362585 payload_small=12 | fragmented: ingress=0 egress=198631
[fixlat] matched=12961 inbound=153479 outbound=199607 mismatch=3884 | rate: 2592 match/sec | latency: min=12.524us avg=15.017us max=42.791us
[traffic] hooks: ingress=2057625 egress=2151385 | scanned: ingress=166439 egress=215469 | filters: payload_zero=393366 payload_small=13 | fragmented: ingress=0 egress=215469
[fixlat] matched=12960 inbound=166439 outbound=216533 mismatch=3966 | rate: 2592 match/sec | latency: min=12.580us avg=15.167us max=368.232us
[traffic] hooks: ingress=2217991 egress=2319287 | scanned: ingress=179397 egress=232246 | filters: payload_zero=424163 payload_small=14 | fragmented: ingress=0 egress=232246
[fixlat] matched=12958 inbound=179397 outbound=233383 mismatch=3892 | rate: 2592 match/sec | latency: min=12.353us avg=15.014us max=72.525us
[traffic] hooks: ingress=2378056 egress=2486500 | scanned: ingress=192353 egress=248846 | filters: payload_zero=454678 payload_small=15 | fragmented: ingress=0 egress=248846
[fixlat] matched=12956 inbound=192353 outbound=250043 mismatch=3704 | rate: 2591 match/sec | latency: min=12.572us avg=14.925us max=64.238us
[traffic] hooks: ingress=2538491 egress=2654226 | scanned: ingress=205319 egress=265603 | filters: payload_zero=485463 payload_small=16 | fragmented: ingress=0 egress=265603
[fixlat] matched=12966 inbound=205319 outbound=266880 mismatch=3871 | rate: 2593 match/sec | latency: min=12.565us avg=14.922us max=66.404us
[traffic] hooks: ingress=2698594 egress=2821589 | scanned: ingress=218284 egress=282233 | filters: payload_zero=515931 payload_small=19 | fragmented: ingress=0 egress=282233
[fixlat] matched=12965 inbound=218284 outbound=283583 mismatch=3738 | rate: 2593 match/sec | latency: min=12.651us avg=14.936us max=56.633us
[traffic] hooks: ingress=2858720 egress=2988914 | scanned: ingress=231245 egress=298986 | filters: payload_zero=546463 payload_small=20 | fragmented: ingress=0 egress=298986
[fixlat] matched=12961 inbound=231245 outbound=300412 mismatch=3868 | rate: 2592 match/sec | latency: min=12.495us avg=14.915us max=66.424us
[traffic] hooks: ingress=3019113 egress=3156588 | scanned: ingress=244203 egress=315693 | filters: payload_zero=577291 payload_small=21 | fragmented: ingress=0 egress=315693
[fixlat] matched=12958 inbound=244203 outbound=317209 mismatch=3839 | rate: 2592 match/sec | latency: min=12.615us avg=14.962us max=573.117us
[traffic] hooks: ingress=3179417 egress=3324145 | scanned: ingress=257165 egress=332516 | filters: payload_zero=607985 payload_small=24 | fragmented: ingress=0 egress=332516
[fixlat] matched=12962 inbound=257165 outbound=334111 mismatch=3940 | rate: 2592 match/sec | latency: min=12.505us avg=14.898us max=49.598us
[traffic] hooks: ingress=3339778 egress=3491717 | scanned: ingress=270128 egress=349239 | filters: payload_zero=638727 payload_small=25 | fragmented: ingress=0 egress=349239
[fixlat] matched=12963 inbound=270128 outbound=350918 mismatch=3844 | rate: 2593 match/sec | latency: min=12.442us avg=15.122us max=326.947us
[traffic] hooks: ingress=3500046 egress=3659358 | scanned: ingress=283083 egress=365912 | filters: payload_zero=669468 payload_small=26 | fragmented: ingress=0 egress=365912
[fixlat] matched=12955 inbound=283083 outbound=367675 mismatch=3802 | rate: 2591 match/sec | latency: min=12.597us avg=15.095us max=94.825us
[traffic] hooks: ingress=3660131 egress=3826566 | scanned: ingress=296039 egress=382619 | filters: payload_zero=700012 payload_small=29 | fragmented: ingress=0 egress=382619
[fixlat] matched=12956 inbound=296039 outbound=384466 mismatch=3835 | rate: 2591 match/sec | latency: min=12.724us avg=15.020us max=66.917us
[traffic] hooks: ingress=3820036 egress=3993720 | scanned: ingress=308980 egress=399285 | filters: payload_zero=730513 payload_small=30 | fragmented: ingress=0 egress=399285
[fixlat] matched=12941 inbound=308980 outbound=401214 mismatch=3807 | rate: 2588 match/sec | latency: min=12.667us avg=15.097us max=45.524us
[traffic] hooks: ingress=3979930 egress=4160839 | scanned: ingress=321926 egress=415884 | filters: payload_zero=760956 payload_small=31 | fragmented: ingress=0 egress=415884
[fixlat] matched=12946 inbound=321926 outbound=417887 mismatch=3727 | rate: 2589 match/sec | latency: min=12.647us avg=15.169us max=71.253us
[traffic] hooks: ingress=4139896 egress=4328038 | scanned: ingress=334878 egress=432485 | filters: payload_zero=791415 payload_small=32 | fragmented: ingress=0 egress=432485
[fixlat] matched=12952 inbound=334878 outbound=434575 mismatch=3736 | rate: 2590 match/sec | latency: min=12.400us avg=14.877us max=62.522us
[traffic] hooks: ingress=4300012 egress=4495475 | scanned: ingress=347836 egress=449275 | filters: payload_zero=821966 payload_small=33 | fragmented: ingress=0 egress=449275
[fixlat] matched=12958 inbound=347836 outbound=451455 mismatch=3922 | rate: 2592 match/sec | latency: min=12.570us avg=15.137us max=511.869us
[traffic] hooks: ingress=4459970 egress=4662647 | scanned: ingress=360794 egress=465932 | filters: payload_zero=852353 payload_small=34 | fragmented: ingress=0 egress=465932
[fixlat] matched=12958 inbound=360794 outbound=468217 mismatch=3804 | rate: 2592 match/sec | latency: min=12.393us avg=15.151us max=58.324us
[traffic] hooks: ingress=4620476 egress=4830512 | scanned: ingress=373765 egress=482675 | filters: payload_zero=883158 payload_small=37 | fragmented: ingress=0 egress=482675
[fixlat] matched=12971 inbound=373765 outbound=485044 mismatch=3856 | rate: 2594 match/sec | latency: min=12.679us avg=14.989us max=88.139us
[traffic] hooks: ingress=4780827 egress=4998221 | scanned: ingress=386727 egress=499544 | filters: payload_zero=913895 payload_small=38 | fragmented: ingress=0 egress=499544
[fixlat] matched=12962 inbound=386727 outbound=502001 mismatch=3995 | rate: 2592 match/sec | latency: min=12.501us avg=14.938us max=58.187us
[traffic] hooks: ingress=4940938 egress=5165534 | scanned: ingress=399678 egress=516285 | filters: payload_zero=944511 payload_small=39 | fragmented: ingress=0 egress=516285
[fixlat] matched=12951 inbound=399678 outbound=518825 mismatch=3873 | rate: 2590 match/sec | latency: min=12.708us avg=14.988us max=327.218us
[traffic] hooks: ingress=5100761 egress=5332696 | scanned: ingress=412630 egress=533009 | filters: payload_zero=974823 payload_small=42 | fragmented: ingress=0 egress=533009
[fixlat] matched=12952 inbound=412630 outbound=535627 mismatch=3850 | rate: 2590 match/sec | latency: min=12.663us avg=14.936us max=68.043us
[traffic] hooks: ingress=5260868 egress=5500093 | scanned: ingress=425581 egress=549865 | filters: payload_zero=1005430 payload_small=43 | fragmented: ingress=0 egress=549865
[fixlat] matched=12951 inbound=425581 outbound=552561 mismatch=3983 | rate: 2590 match/sec | latency: min=12.701us avg=14.924us max=67.769us
[traffic] hooks: ingress=5421038 egress=5667624 | scanned: ingress=438534 egress=566574 | filters: payload_zero=1036079 payload_small=44 | fragmented: ingress=0 egress=566574
[fixlat] matched=12953 inbound=438534 outbound=569355 mismatch=3841 | rate: 2591 match/sec | latency: min=12.693us avg=14.892us max=64.206us
[traffic] hooks: ingress=5580717 egress=5834448 | scanned: ingress=451486 egress=583113 | filters: payload_zero=1066243 payload_small=47 | fragmented: ingress=0 egress=583113
[fixlat] matched=12952 inbound=451486 outbound=585971 mismatch=3664 | rate: 2590 match/sec | latency: min=12.192us avg=14.894us max=57.541us
[traffic] hooks: ingress=5740943 egress=6001946 | scanned: ingress=464431 egress=599944 | filters: payload_zero=1097033 payload_small=48 | fragmented: ingress=0 egress=599944
[fixlat] matched=12945 inbound=464431 outbound=602883 mismatch=3967 | rate: 2589 match/sec | latency: min=12.224us avg=14.970us max=328.099us
[traffic] hooks: ingress=5900752 egress=6168983 | scanned: ingress=477373 egress=616516 | filters: payload_zero=1127425 payload_small=49 | fragmented: ingress=0 egress=616516
[fixlat] matched=12942 inbound=477373 outbound=619523 mismatch=3698 | rate: 2588 match/sec | latency: min=12.624us avg=15.239us max=42.156us
[traffic] hooks: ingress=6060849 egress=6336284 | scanned: ingress=490321 egress=633345 | filters: payload_zero=1158050 payload_small=50 | fragmented: ingress=0 egress=633345
[fixlat] matched=12948 inbound=490321 outbound=636434 mismatch=3963 | rate: 2590 match/sec | latency: min=12.560us avg=15.219us max=47.375us
[traffic] hooks: ingress=6220932 egress=6503593 | scanned: ingress=503271 egress=650019 | filters: payload_zero=1188640 payload_small=51 | fragmented: ingress=0 egress=650019
[fixlat] matched=12950 inbound=503271 outbound=653188 mismatch=3804 | rate: 2590 match/sec | latency: min=12.643us avg=14.998us max=51.015us
[traffic] hooks: ingress=6381029 egress=6670936 | scanned: ingress=516232 egress=666680 | filters: payload_zero=1219140 payload_small=52 | fragmented: ingress=0 egress=666680
[fixlat] matched=12961 inbound=516232 outbound=669928 mismatch=3779 | rate: 2592 match/sec | latency: min=12.631us avg=14.956us max=62.381us
[traffic] hooks: ingress=6541393 egress=6838626 | scanned: ingress=529204 egress=683466 | filters: payload_zero=1249795 payload_small=53 | fragmented: ingress=0 egress=683466
[fixlat] matched=12972 inbound=529204 outbound=686781 mismatch=3881 | rate: 2594 match/sec | latency: min=12.461us avg=14.971us max=51.909us
[traffic] hooks: ingress=6701691 egress=7006183 | scanned: ingress=542159 egress=700146 | filters: payload_zero=1280547 payload_small=54 | fragmented: ingress=0 egress=700146
[fixlat] matched=12955 inbound=542159 outbound=703543 mismatch=3807 | rate: 2591 match/sec | latency: min=12.669us avg=15.019us max=203.636us
[traffic] hooks: ingress=6861726 egress=7173557 | scanned: ingress=555102 egress=716903 | filters: payload_zero=1311168 payload_small=55 | fragmented: ingress=0 egress=716903
[fixlat] matched=12943 inbound=555102 outbound=720372 mismatch=3886 | rate: 2589 match/sec | latency: min=12.502us avg=15.433us max=501.993us
[traffic] hooks: ingress=7021678 egress=7340980 | scanned: ingress=568044 egress=733502 | filters: payload_zero=1341707 payload_small=56 | fragmented: ingress=0 egress=733502
[fixlat] matched=12942 inbound=568044 outbound=737061 mismatch=3747 | rate: 2588 match/sec | latency: min=12.637us avg=14.966us max=55.218us
[traffic] hooks: ingress=7181597 egress=7508093 | scanned: ingress=580995 egress=750282 | filters: payload_zero=1372132 payload_small=57 | fragmented: ingress=0 egress=750282
[fixlat] matched=12951 inbound=580995 outbound=753919 mismatch=3907 | rate: 2590 match/sec | latency: min=12.624us avg=14.930us max=70.170us
[traffic] hooks: ingress=7341834 egress=7675607 | scanned: ingress=593947 egress=767090 | filters: payload_zero=1402878 payload_small=58 | fragmented: ingress=0 egress=767090
[fixlat] matched=12952 inbound=593947 outbound=770821 mismatch=3950 | rate: 2590 match/sec | latency: min=12.271us avg=14.986us max=67.029us
[traffic] hooks: ingress=7501785 egress=7842825 | scanned: ingress=606897 egress=783819 | filters: payload_zero=1433335 payload_small=59 | fragmented: ingress=0 egress=783819
[fixlat] matched=12950 inbound=606897 outbound=787632 mismatch=3861 | rate: 2590 match/sec | latency: min=12.717us avg=14.948us max=194.439us
[traffic] hooks: ingress=7661659 egress=8009890 | scanned: ingress=619846 egress=800591 | filters: payload_zero=1463732 payload_small=60 | fragmented: ingress=0 egress=800591
[fixlat] matched=12949 inbound=619846 outbound=804492 mismatch=3911 | rate: 2590 match/sec | latency: min=12.461us avg=14.979us max=73.004us
[traffic] hooks: ingress=7821585 egress=8177032 | scanned: ingress=632793 egress=817291 | filters: payload_zero=1494193 payload_small=61 | fragmented: ingress=0 egress=817291
[fixlat] matched=12947 inbound=632793 outbound=821263 mismatch=3824 | rate: 2589 match/sec | latency: min=12.584us avg=14.992us max=63.963us
[traffic] hooks: ingress=7981435 egress=8344093 | scanned: ingress=645742 egress=833910 | filters: payload_zero=1524558 payload_small=62 | fragmented: ingress=0 egress=833910
[fixlat] matched=12949 inbound=645742 outbound=837964 mismatch=3752 | rate: 2590 match/sec | latency: min=12.582us avg=14.968us max=62.927us
[traffic] hooks: ingress=8141693 egress=8511706 | scanned: ingress=658691 egress=850629 | filters: payload_zero=1555340 payload_small=63 | fragmented: ingress=0 egress=850629
[fixlat] matched=12949 inbound=658691 outbound=854761 mismatch=3848 | rate: 2590 match/sec | latency: min=12.577us avg=15.220us max=74.561us
[traffic] hooks: ingress=8301814 egress=8678971 | scanned: ingress=671650 egress=867340 | filters: payload_zero=1585894 payload_small=64 | fragmented: ingress=0 egress=867340
[fixlat] matched=12959 inbound=671650 outbound=871559 mismatch=3839 | rate: 2592 match/sec | latency: min=12.633us avg=15.609us max=644.566us
[traffic] hooks: ingress=8462147 egress=8846490 | scanned: ingress=684621 egress=884072 | filters: payload_zero=1616520 payload_small=65 | fragmented: ingress=0 egress=884072
[fixlat] matched=12971 inbound=684621 outbound=888365 mismatch=3835 | rate: 2594 match/sec | latency: min=12.236us avg=14.922us max=59.915us
[traffic] hooks: ingress=8622415 egress=9013916 | scanned: ingress=697576 egress=900782 | filters: payload_zero=1647269 payload_small=66 | fragmented: ingress=0 egress=900782
[fixlat] matched=12955 inbound=697576 outbound=905162 mismatch=3842 | rate: 2591 match/sec | latency: min=12.522us avg=14.924us max=60.725us
[traffic] hooks: ingress=8782878 egress=9181846 | scanned: ingress=710524 egress=917473 | filters: payload_zero=1678274 payload_small=67 | fragmented: ingress=0 egress=917473
[fixlat] matched=12948 inbound=710524 outbound=921918 mismatch=3808 | rate: 2590 match/sec | latency: min=12.245us avg=14.973us max=378.767us
[traffic] hooks: ingress=8943432 egress=9349778 | scanned: ingress=723485 egress=934293 | filters: payload_zero=1709227 payload_small=68 | fragmented: ingress=0 egress=934293
[fixlat] matched=12961 inbound=723485 outbound=938833 mismatch=3954 | rate: 2592 match/sec | latency: min=12.676us avg=14.931us max=56.008us
[traffic] hooks: ingress=9103345 egress=9516991 | scanned: ingress=736439 egress=950946 | filters: payload_zero=1739602 payload_small=69 | fragmented: ingress=0 egress=950946
[fixlat] matched=12954 inbound=736439 outbound=955566 mismatch=3779 | rate: 2591 match/sec | latency: min=12.479us avg=14.839us max=57.192us
[traffic] hooks: ingress=9263611 egress=9684474 | scanned: ingress=749395 egress=967928 | filters: payload_zero=1770324 payload_small=70 | fragmented: ingress=0 egress=967928
[fixlat] matched=12956 inbound=749395 outbound=972624 mismatch=4102 | rate: 2591 match/sec | latency: min=12.182us avg=15.300us max=521.629us
[traffic] hooks: ingress=9424088 egress=9852257 | scanned: ingress=762350 egress=984677 | filters: payload_zero=1801265 payload_small=71 | fragmented: ingress=0 egress=984677
[fixlat] matched=12955 inbound=762350 outbound=989434 mismatch=3855 | rate: 2591 match/sec | latency: min=12.494us avg=14.995us max=66.345us
[traffic] hooks: ingress=9584112 egress=10019504 | scanned: ingress=775304 egress=1001309 | filters: payload_zero=1831756 payload_small=72 | fragmented: ingress=0 egress=1001309
[fixlat] matched=12954 inbound=775304 outbound=1006143 mismatch=3755 | rate: 2591 match/sec | latency: min=12.553us avg=14.985us max=75.507us
[traffic] hooks: ingress=9744298 egress=10186937 | scanned: ingress=788255 egress=1018014 | filters: payload_zero=1862440 payload_small=73 | fragmented: ingress=0 egress=1018014
[fixlat] matched=12951 inbound=788255 outbound=1022926 mismatch=3832 | rate: 2590 match/sec | latency: min=12.182us avg=14.955us max=77.095us
[traffic] hooks: ingress=9904765 egress=10354839 | scanned: ingress=801210 egress=1034654 | filters: payload_zero=1893362 payload_small=74 | fragmented: ingress=0 egress=1034654
[fixlat] matched=12955 inbound=801210 outbound=1039648 mismatch=3767 | rate: 2591 match/sec | latency: min=12.365us avg=14.984us max=56.426us
[traffic] hooks: ingress=10064611 egress=10521797 | scanned: ingress=814161 egress=1051404 | filters: payload_zero=1923710 payload_small=75 | fragmented: ingress=0 egress=1051404
[fixlat] matched=12951 inbound=814161 outbound=1056464 mismatch=3865 | rate: 2590 match/sec | latency: min=12.461us avg=14.886us max=70.477us
[traffic] hooks: ingress=10224817 egress=10689292 | scanned: ingress=827125 egress=1068277 | filters: payload_zero=1954288 payload_small=76 | fragmented: ingress=0 egress=1068277
[fixlat] matched=12964 inbound=827125 outbound=1073434 mismatch=4006 | rate: 2593 match/sec | latency: min=12.620us avg=15.084us max=72.219us
[traffic] hooks: ingress=10385653 egress=10857550 | scanned: ingress=840098 egress=1085121 | filters: payload_zero=1985395 payload_small=83 | fragmented: ingress=0 egress=1085121
[fixlat] matched=12973 inbound=840098 outbound=1090368 mismatch=3961 | rate: 2595 match/sec | latency: min=12.606us avg=15.036us max=46.162us
[traffic] hooks: ingress=10545965 egress=11025227 | scanned: ingress=853062 egress=1101674 | filters: payload_zero=2016100 payload_small=84 | fragmented: ingress=0 egress=1101674
[fixlat] matched=12963 inbound=853062 outbound=1106998 mismatch=3667 | rate: 2593 match/sec | latency: min=12.645us avg=15.263us max=348.193us
[pending] active=0/16384 stale_evicted=1 forced=0
[traffic] hooks: ingress=10706323 egress=11193089 | scanned: ingress=866015 egress=1118316 | filters: payload_zero=2046947 payload_small=85 | fragmented: ingress=0 egress=1118316
[fixlat] matched=12953 inbound=866015 outbound=1123723 mismatch=3772 | rate: 2591 match/sec | latency: min=12.574us avg=14.999us max=300.188us
[pending] active=0/16384 stale_evicted=1 forced=0
[traffic] hooks: ingress=10865988 egress=11359892 | scanned: ingress=878968 egress=1134965 | filters: payload_zero=2077086 payload_small=86 | fragmented: ingress=0 egress=1134965
[fixlat] matched=12953 inbound=878968 outbound=1140462 mismatch=3786 | rate: 2591 match/sec | latency: min=12.373us avg=14.916us max=52.520us
[pending] active=0/16384 stale_evicted=1 forced=0
[traffic] hooks: ingress=11026195 egress=11527549 | scanned: ingress=891917 egress=1151625 | filters: payload_zero=2107819 payload_small=87 | fragmented: ingress=0 egress=1151625
[fixlat] matched=12949 inbound=891917 outbound=1157193 mismatch=3781 | rate: 2590 match/sec | latency: min=12.582us avg=14.873us max=55.256us
[pending] active=0/16384 stale_evicted=1 forced=0
[traffic] hooks: ingress=11186322 egress=11695051 | scanned: ingress=904879 egress=1168381 | filters: payload_zero=2138356 payload_small=88 | fragmented: ingress=0 egress=1168381
[fixlat] matched=12962 inbound=904879 outbound=1174021 mismatch=3867 | rate: 2592 match/sec | latency: min=12.225us avg=14.960us max=52.835us
[pending] active=0/16384 stale_evicted=1 forced=0
[traffic] hooks: ingress=11346580 egress=11862587 | scanned: ingress=917832 egress=1185257 | filters: payload_zero=2169092 payload_small=89 | fragmented: ingress=0 egress=1185257
[fixlat] matched=12953 inbound=917832 outbound=1190970 mismatch=3996 | rate: 2591 match/sec | latency: min=12.558us avg=14.960us max=56.598us
[pending] active=0/16384 stale_evicted=1 forced=0
[traffic] hooks: ingress=11506661 egress=12030054 | scanned: ingress=930777 egress=1202094 | filters: payload_zero=2199740 payload_small=90 | fragmented: ingress=0 egress=1202094
[fixlat] matched=12945 inbound=930777 outbound=1207881 mismatch=3966 | rate: 2589 match/sec | latency: min=12.487us avg=15.235us max=685.093us
[pending] active=0/16384 stale_evicted=1 forced=0
[traffic] hooks: ingress=11666509 egress=12197260 | scanned: ingress=943713 egress=1218985 | filters: payload_zero=2230235 payload_small=91 | fragmented: ingress=0 egress=1218985
[fixlat] matched=12936 inbound=943713 outbound=1224851 mismatch=4034 | rate: 2587 match/sec | latency: min=12.348us avg=15.030us max=50.636us
[pending] active=0/16384 stale_evicted=1 forced=0
[traffic] hooks: ingress=11826341 egress=12364318 | scanned: ingress=956668 egress=1235675 | filters: payload_zero=2260524 payload_small=92 | fragmented: ingress=0 egress=1235675
[fixlat] matched=12955 inbound=956668 outbound=1241624 mismatch=3818 | rate: 2591 match/sec | latency: min=12.287us avg=14.868us max=55.007us
[pending] active=0/16384 stale_evicted=1 forced=0

========== CUMULATIVE HISTOGRAM (all-time, n=963266) ==========
MIN:      12.049us
P50:      14.449us
P90:      17.649us
P99:      19.949us
P99.9:    35.749us
P99.99:   61.849us
P99.999:  492.499us
MAX:      685.499us

Distribution:
  12.0us-17.7us |################################################## 876987 (91.0%)
  17.8us-23.5us |#### 82898 (8.6%)
  23.6us-29.3us | 1784 (0.2%)
  29.4us-35.1us | 582 (0.1%)
  35.2us-40.9us | 386 (0.0%)
  41.0us-46.7us | 315 (0.0%)
  46.8us-52.5us | 126 (0.0%)
  52.6us-58.3us | 69 (0.0%)
  58.4us-64.1us | 34 (0.0%)
  64.2us-69.9us | 21 (0.0%)
  70.0us-75.7us | 10 (0.0%)
  75.8us-81.5us | 4 (0.0%)
  87.4us-93.1us | 3 (0.0%)
  93.2us-98.9us | 2 (0.0%)
 99.0us-147.5us | 5 (0.0%)
148.5us-205.5us | 7 (0.0%)
206.5us-263.5us | 7 (0.0%)
264.5us-321.5us | 2 (0.0%)
322.5us-379.5us | 9 (0.0%)
380.5us-437.5us | 3 (0.0%)
438.5us-495.5us | 2 (0.0%)
496.5us-553.5us | 4 (0.0%)
554.5us-611.5us | 3 (0.0%)
612.5us-669.5us | 2 (0.0%)
670.5us-685.5us | 1 (0.0%)
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