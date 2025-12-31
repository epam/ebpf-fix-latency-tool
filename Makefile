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
USEROBJ   := user/fixlat
TESTOBJ   := test/test_parser_logic

all: $(USEROBJ)

$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPFOBJ): bpf/fixlat.bpf.c $(VMLINUX)
	$(BPF_CLANG) -g -Oz -target bpf -D__TARGET_ARCH_x86 -D__BPF__  \
       -fno-unroll-loops  \
	  -I. -Ibpf -Iinclude -c $< -o $@

$(SKEL): $(BPFOBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(USEROBJ): user/fixlat.c $(SKEL)
	$(CC) $(CFLAGS) -Ibpf -Iinclude user/fixlat.c -o $@ $(PKG)

# Static build for distribution (bundles libbpf)
static: user/fixlat.c $(SKEL)
	$(CC) $(CFLAGS) -Ibpf -Iinclude user/fixlat.c -o $(USEROBJ)-static \
		-static -lbpf -lelf -lz -lzstd

$(TESTOBJ): test/test_parser_logic.c include/fixlat.h
	$(CC) $(CFLAGS) -Iinclude test/test_parser_logic.c -o $@

test: $(TESTOBJ)
	@echo "Running parser unit tests..."
	@./$(TESTOBJ)

verify: $(BPFOBJ)
	@echo "Verifying eBPF programs..."
	@sudo $(BPFTOOL) prog loadall $(BPFOBJ) /sys/fs/bpf/fixlat_verify type tc
	@echo "✓ All programs passed eBPF verifier"
	@sudo rm -rf /sys/fs/bpf/fixlat_verify

clean:
	rm -f $(VMLINUX) $(BPFOBJ) $(SKEL) $(USEROBJ) $(USEROBJ)-static $(TESTOBJ)
	rm -f fixlat-$(VERSION).zip fixlat-$(VERSION)/fixlat
	rmdir fixlat-$(VERSION) 2>/dev/null || true

# Create distribution ZIP with version suffix
dist: static
	@echo "Creating distribution package: fixlat-$(VERSION).zip"
	@mkdir -p fixlat-$(VERSION)
	@cp $(USEROBJ)-static fixlat-$(VERSION)/fixlat
	@chmod +x fixlat-$(VERSION)/fixlat
	@zip -q fixlat-$(VERSION).zip fixlat-$(VERSION)/fixlat
	@rm -rf fixlat-$(VERSION)
	@echo "Created: fixlat-$(VERSION).zip"

.PHONY: all test verify clean static dist
