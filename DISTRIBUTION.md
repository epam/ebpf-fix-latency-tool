# Distribution Guide

## Overview

This eBPF latency monitoring tool uses **BPF CO-RE** (Compile Once, Run Everywhere), which means binaries compiled on one machine can run on different kernel versions without recompilation.

## Distribution Options

### Option 1: Source Distribution

Ship source code and build on target server.

**On Amazon Linux 2023:**
```bash
# Install build dependencies
sudo dnf install -y clang llvm libbpf-devel kernel-devel bpftool

# Build
make

# Run
sudo ./user/ebpf-fix-latency-tool -i eth0 -p 8080 -r 5
```

**Pros:**
- Works across any kernel version
- Easy to modify and rebuild
- Smallest distribution size

**Cons:**
- Requires build tools on target
- Longer deployment time

---

### Option 2: Static Binary Distribution (Recommended for Production)

Build a single static binary that bundles all dependencies except the kernel.

**Build static binary (on dev machine):**
```bash
# Install static libraries (if not already installed)
# Ubuntu/Debian:
sudo apt install -y libbpf-dev libelf-dev zlib1g-dev libzstd-dev

# Build static binary
make static

# Result: user/ebpf-fix-latency-tool-static (single 2.2MB binary)

# Or create distribution ZIP (recommended)
make dist

# Result: ebpf-fix-latency-tool-0.0.2.zip containing ebpf-fix-latency-tool-0.0.2/ebpf-fix-latency-tool
```

**Deploy to target server:**
```bash
# Copy binary to target
scp user/ebpf-fix-latency-tool-static ec2-user@server:/usr/local/bin/ebpf-fix-latency-tool

# Run (no dependencies needed!)
sudo /usr/local/bin/ebpf-fix-latency-tool -i eth0 -p 8080 -r 5

# Or with port range
sudo /usr/local/bin/ebpf-fix-latency-tool -i eth0 -p 12001-12010 -r 5
```

**Pros:**
- Single binary, no runtime dependencies
- Fast deployment
- Works on any Linux distro with BPF support

**Cons:**
- Larger binary size (2.2MB vs 145KB)
- Must rebuild for different architectures (x86_64 vs ARM)

---

### Option 3: Dynamic Binary Distribution

Ship pre-compiled binary that depends on system libbpf.

**Build dynamic binary (on dev machine):**
```bash
make
```

**Deploy to target server:**
```bash
# Install runtime dependency only
sudo dnf install -y libbpf

# Copy binary
scp user/ebpf-fix-latency-tool ec2-user@server:/usr/local/bin/ebpf-fix-latency-tool

# Run
sudo /usr/local/bin/ebpf-fix-latency-tool -i eth0 -p 8080 -r 5
```

**Pros:**
- Smaller binary size (145KB)
- Shares system libbpf library

**Cons:**
- Requires libbpf on target
- libbpf version must be compatible

---

## Kernel Requirements

**Minimum kernel version:** 5.10+ (Amazon Linux 2023 ships with 6.1+, so you're good!)

**Required kernel features:**
- CONFIG_BPF=y
- CONFIG_BPF_SYSCALL=y
- CONFIG_NET_CLS_BPF=y
- CONFIG_NET_SCH_INGRESS=y
- CONFIG_BPF_JIT=y

Amazon Linux 2023 has all these enabled by default.

---

## Recommended Deployment Workflow

### For Production Cloud Servers:

1. **Build distribution package on CI/build server:**
   ```bash
   make dist
   # Creates: ebpf-fix-latency-tool-0.0.2.zip
   ```

2. **Deploy to target:**
   ```bash
   # Extract
   unzip ebpf-fix-latency-tool-0.0.2.zip
   sudo cp ebpf-fix-latency-tool-0.0.2/ebpf-fix-latency-tool /usr/local/bin/

   # Run (single port)
   sudo /usr/local/bin/ebpf-fix-latency-tool -i eth0 -p 8080 -r 5

   # Run (port range)
   sudo /usr/local/bin/ebpf-fix-latency-tool -i eth0 -p 12001-12010 -r 5
   ```

3. **Optional: Create systemd service:**
   ```bash
   cat > /etc/systemd/system/ebpf-fix-latency-tool.service <<EOF
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
   EOF

   sudo systemctl daemon-reload
   sudo systemctl enable ebpf-fix-latency-tool
   sudo systemctl start ebpf-fix-latency-tool
   ```

---

## Verifying BPF Support on Target

```bash
# Check kernel version
uname -r

# Verify BPF syscall support
sudo bpftool version

# If bpftool not available, test with simple check:
sudo cat /proc/sys/kernel/bpf_disabled
# Should return 0 (BPF enabled)
```

---

## Architecture Support

This tool currently targets **x86_64**. For ARM64 (Graviton instances):

1. Change Makefile line 21:
   ```makefile
   -D__TARGET_ARCH_x86  →  -D__TARGET_ARCH_arm64
   ```

2. Rebuild on ARM64 machine or use cross-compilation.
