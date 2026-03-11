# BPF program compilation for OAIE eBPF tracer.
#
# Prerequisites:
#   - clang >= 14 (clang-18 recommended)
#   - bpftool (for vmlinux.h generation)
#   - libbpf headers (libbpf-dev on Debian/Ubuntu)
#
# Targets:
#   make          — compile all BPF programs
#   make vmlinux  — generate vmlinux.h from running kernel's BTF
#   make clean    — remove compiled objects
#   make prebuilt — copy compiled objects to prebuilt/

CLANG ?= clang
BPFTOOL ?= bpftool

# BPF compilation flags.
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86

# Include paths for libbpf headers.
# libbpf-dev installs to /usr/include/bpf; kernel headers include libbpf
# under tools/bpf/resolve_btfids/libbpf/include/.
KERNEL_HEADERS := /usr/src/linux-headers-$(shell uname -r)
BPF_INCLUDES := -I. \
    -I$(KERNEL_HEADERS)/tools/bpf/resolve_btfids/libbpf/include

PROGS := oaie_tracer.bpf.o

.PHONY: all clean gen-vmlinux prebuilt

all: $(PROGS)

%.bpf.o: %.bpf.c oaie_events.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) $(BPF_INCLUDES) -c $< -o $@

gen-vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Copy compiled objects to prebuilt/ for builds without clang/bpftool.
prebuilt: $(PROGS)
	cp $(PROGS) prebuilt/

clean:
	rm -f $(PROGS)
