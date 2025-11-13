# fixlat-kfifo Makefile (standalone build)
# Works on Ubuntu 24 with libbpf-dev installed.

BPF_CLANG ?= clang
BPFTOOL   ?= bpftool
CFLAGS    += -O2 -g -Wall -Iinclude -I/usr/include -L/usr/lib/x86_64-linux-gnu
LDLIBS    += -lbpf -lelf -lz

BPF_SRC   := bpf/fixlat.bpf.c
BPF_OBJ   := build/fixlat.bpf.o
SKEL_H    := build/user/fixlat.skel.h
USER_SRC  := user/fixlat.c
USER_BIN  := build/fixlat

.PHONY: all clean

all: $(USER_BIN)

# --- BPF object ---
$(BPF_OBJ): $(BPF_SRC) include/fixlat.h | build
