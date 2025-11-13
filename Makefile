# Makefile (minimal libbpf CO-RE build)

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

all: $(USEROBJ)

$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPFOBJ): bpf/fixlat.bpf.c $(VMLINUX)
	$(BPF_CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 -D__BPF__ \
	  -I. -Ibpf -Iinclude -c $< -o $@

$(SKEL): $(BPFOBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(USEROBJ): user/fixlat.c $(SKEL)
	$(CC) $(CFLAGS) -Ibpf -Iinclude user/fixlat.c -o $@ $(PKG)

clean:
	rm -f $(VMLINUX) $(BPFOBJ) $(SKEL) $(USEROBJ)

.PHONY: all clean
