# fixlat-kfifo

Kernel-side FIFO correlation using BPF queue map; in-kernel log2 histogram of latency (µs). Userspace polls & resets histogram.

## Build
sudo apt update
sudo apt install -y clang llvm make cmake pkg-config libelf-dev libbpf-dev bpftool
mkdir build && cd build
cmake ..
make -j

## Run
sudo ./fixlat -i <iface> -d <fix_port> -r 5

## Detach
sudo tc qdisc del dev <iface> clsact 2>/dev/null || true
