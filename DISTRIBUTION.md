# Distribution Guide

This tool is distributed as a static binary or from source. It's portable across kernel versions because it only accesses stable network protocol headers (IP, TCP, Ethernet), not kernel internals.

**GitHub:** https://github.com/epam/ebpf-fix-latency-tool

## Quick Start - Download Pre-Built Binary

Fastest way to deploy:

```bash
# Download latest release
wget https://github.com/epam/ebpf-fix-latency-tool/releases/latest/download/ebpf-fix-latency-tool-static

# Install
sudo install -m 755 ebpf-fix-latency-tool-static /usr/local/bin/ebpf-fix-latency-tool

# Run
sudo ebpf-fix-latency-tool -i eth0 -p 8080 -r 5
```

The static binary (~2.3MB) has zero runtime dependencies. Works on any Linux with kernel 5.10+ and BPF support.

## Building From Source

### Prerequisites

Ubuntu/Debian:
```bash
sudo apt install -y clang llvm libbpf-dev libelf-dev bpftool zlib1g-dev libzstd-dev
```

RHEL/Amazon Linux:
```bash
sudo dnf install -y clang llvm libbpf-devel kernel-devel bpftool
```

### Build

```bash
git clone https://github.com/epam/ebpf-fix-latency-tool.git
cd ebpf-fix-latency-tool
make
```

This produces `user/ebpf-fix-latency-tool` (~184KB, needs libbpf runtime).

For a self-contained binary:
```bash
make static
# Creates user/ebpf-fix-latency-tool-static (~2.3MB)
```

For a distribution package:
```bash
make dist
# Creates ebpf-fix-latency-tool-VERSION.zip
```

## Deployment Options

### Static Binary (Recommended)

Single binary, no dependencies. Either download from GitHub releases or build with `make static`.

```bash
scp user/ebpf-fix-latency-tool-static server:/usr/local/bin/ebpf-fix-latency-tool
```

### Dynamic Binary

Smaller (184KB) but requires libbpf on target:

```bash
# On target
sudo dnf install -y libbpf

# Deploy
scp user/ebpf-fix-latency-tool server:/usr/local/bin/
```

### Source Distribution

Clone repo on target and `make`. Useful if you need to modify code or build for unusual architectures.

## Running as a Service

Create `/etc/systemd/system/ebpf-fix-latency-tool.service`:

```ini
[Unit]
Description=eBPF FIX Protocol Latency Monitor
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ebpf-fix-latency-tool -i eth0 -p 8080 -r 5
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

Then:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ebpf-fix-latency-tool
sudo journalctl -u ebpf-fix-latency-tool -f
```

Common options in `ExecStart`:
- Port range: `-p 12001-12010`
- CPU pinning: `-c 3`
- Custom histogram: `-x 500`

## Kernel Requirements

Minimum kernel 5.10. Tested on Ubuntu 24.04 (6.14) and Amazon Linux 2 (5.10).

Required features (enabled by default on modern distros):
- CONFIG_BPF=y
- CONFIG_BPF_SYSCALL=y
- CONFIG_NET_CLS_BPF=y
- CONFIG_NET_SCH_INGRESS=y
- CONFIG_BPF_JIT=y

Verify BPF support:
```bash
uname -r
sudo bpftool version
cat /proc/sys/kernel/bpf_disabled  # Should be 0
```

## CI/CD and Releases

The repo has GitHub Actions that build and test on every push. Releases are automated when you push a version tag.

To create a release:
```bash
echo "0.0.6" > VERSION
git add VERSION
git commit -m "Release v0.0.6"
git tag v0.0.6
git push origin master v0.0.6
```

GitHub Actions will build binaries and create a release automatically. See `.github/workflows/release.yml` for details.

CI runs tests on every PR and keeps build artifacts for 30 days.

## Architecture Support

Works on x86_64 and ARM64. Just build natively on the target architecture - the Makefile handles it.

For cross-compilation to ARM64, change `-D__TARGET_ARCH_x86` to `-D__TARGET_ARCH_arm64` in the Makefile. Though honestly, it's easier to just build on an ARM64 box.

## Common Issues

**"eBPF not available" / permission errors**
Run with sudo. eBPF needs root or CAP_BPF capability.

**"libbpf.so.0: cannot open shared object file"**
Use the static binary or install libbpf.

**"Exclusivity flag on, cannot modify"**
Harmless. TC qdisc already exists. Tool works fine.

**"Exec format error"**
Architecture mismatch - you're probably running x86_64 binary on ARM64 or vice versa.

## Security Notes

The tool requires root to load eBPF programs. If you want to avoid full root, use capabilities:

```bash
sudo setcap cap_bpf,cap_net_admin,cap_sys_admin+eip /usr/local/bin/ebpf-fix-latency-tool
```

(Note: CAP_BPF needs kernel 5.8+. Use CAP_SYS_ADMIN on older kernels.)

The tool only monitors traffic, doesn't generate any. No firewall changes needed.

## Size Comparison

| Method | Size | Dependencies | Notes |
|--------|------|--------------|-------|
| GitHub release | 2.3MB | None | Easiest |
| `make static` | 2.3MB | Build-time only | Same as above but you build it |
| `make` | 184KB | Needs libbpf | Smaller but less portable |
| Source | ~100KB | Build + runtime | For development |

---

**See also:**
- [README.md](README.md) - Main docs
- [GitHub Releases](https://github.com/epam/ebpf-fix-latency-tool/releases) - Download binaries
- [CI](.github/workflows/ci.yml) / [Release](.github/workflows/release.yml) workflows
