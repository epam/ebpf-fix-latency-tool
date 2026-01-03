# Makefile (minimal libbpf CO-RE build)

VERSION   := $(shell cat VERSION)
BPF_CLANG ?= clang
BPFTOOL   ?= $(shell find /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1)
CC        ?= cc
CFLAGS    ?= -O2 -g -Wall -Wextra
LDFLAGS   ?=
PKG       := $(shell pkg-config --cflags --libs libbpf 2>/dev/null)
VMLINUX   := bpf/vmlinux.h
BPFOBJ    := bpf/fixlat.bpf.o
SKEL      := bpf/fixlat.skel.h
USEROBJ   := user/ebpf-fix-latency-tool
TESTOBJ   := test/test_parser_logic
HDRTESTOBJ := test/test_hdr_histogram
PENDINGMAPTESTOBJ := test/test_pending_map

all: $(USEROBJ)

# Generate vmlinux.h if it doesn't exist
# Note: vmlinux.h is committed to repo for CI (GitHub Actions lacks BTF support)
$(VMLINUX):
	@echo "Generating vmlinux.h from /sys/kernel/btf/vmlinux..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Explicit target to regenerate vmlinux.h from local kernel
vmlinux-regenerate:
	@echo "Regenerating vmlinux.h from local kernel BTF..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)
	@echo "✓ vmlinux.h regenerated ($(shell wc -l < $(VMLINUX)) lines)"

$(BPFOBJ): bpf/fixlat.bpf.c $(VMLINUX)
	$(BPF_CLANG) -g -Oz -target bpf -D__TARGET_ARCH_x86 -D__BPF__  \
       -fno-unroll-loops  \
	  -I. -Ibpf -Iinclude -c $< -o $@

$(SKEL): $(BPFOBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(USEROBJ): user/fixlat.c $(SKEL)
	$(CC) $(CFLAGS) -DVERSION="\"$(VERSION)\"" -Ibpf -Iinclude user/fixlat.c -o $@ $(PKG)

# Static build for distribution (bundles libbpf)
static: user/fixlat.c $(SKEL)
	$(CC) $(CFLAGS) -DVERSION="\"$(VERSION)\"" -Ibpf -Iinclude user/fixlat.c -o $(USEROBJ)-static \
		-static -lbpf -lelf -lz -lzstd

$(TESTOBJ): test/test_parser_logic.c include/fixlat.h
	$(CC) $(CFLAGS) -Iinclude test/test_parser_logic.c -o $@

$(HDRTESTOBJ): test/test_hdr_histogram.c
	$(CC) $(CFLAGS) test/test_hdr_histogram.c -o $@

$(PENDINGMAPTESTOBJ): test/test_pending_map.c include/fixlat.h
	$(CC) $(CFLAGS) -Iinclude test/test_pending_map.c -o $@

test: $(TESTOBJ) $(HDRTESTOBJ) $(PENDINGMAPTESTOBJ)
	@echo "Running parser unit tests..."
	@./$(TESTOBJ)
	@echo ""
	@echo "Running HDR histogram unit tests..."
	@./$(HDRTESTOBJ)
	@echo ""
	@echo "Running pending map unit tests..."
	@./$(PENDINGMAPTESTOBJ)

verify: $(BPFOBJ)
	@echo "Verifying eBPF programs..."
	@sudo $(BPFTOOL) prog loadall $(BPFOBJ) /sys/fs/bpf/fixlat_verify type tc
	@echo "✓ All programs passed eBPF verifier"
	@sudo rm -rf /sys/fs/bpf/fixlat_verify

clean:
	rm -f $(BPFOBJ) $(SKEL) $(USEROBJ) $(USEROBJ)-static $(TESTOBJ) $(HDRTESTOBJ) $(PENDINGMAPTESTOBJ)
	rm -f ebpf-fix-latency-tool-$(VERSION).zip ebpf-fix-latency-tool-$(VERSION)/ebpf-fix-latency-tool
	rmdir ebpf-fix-latency-tool-$(VERSION) 2>/dev/null || true

# Clean everything including committed vmlinux.h (for local development)
distclean: clean
	rm -f $(VMLINUX)

# Create distribution ZIP with version suffix
dist: static
	@echo "Creating distribution package: ebpf-fix-latency-tool-$(VERSION).zip"
	@mkdir -p ebpf-fix-latency-tool-$(VERSION)
	@cp $(USEROBJ)-static ebpf-fix-latency-tool-$(VERSION)/ebpf-fix-latency-tool
	@chmod +x ebpf-fix-latency-tool-$(VERSION)/ebpf-fix-latency-tool
	@zip -q ebpf-fix-latency-tool-$(VERSION).zip ebpf-fix-latency-tool-$(VERSION)/ebpf-fix-latency-tool
	@rm -rf ebpf-fix-latency-tool-$(VERSION)
	@echo "Created: ebpf-fix-latency-tool-$(VERSION).zip"

.PHONY: all test verify clean distclean static dist vmlinux-regenerate
