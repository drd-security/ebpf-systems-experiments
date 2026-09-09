CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool
ARCH ?= x86
CFLAGS ?= -O2 -g -Wall -Wextra
BPF_CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH)
CHALLENGE ?= antidebug
DIR := challenges/$(CHALLENGE)

.PHONY: all clean vmlinux
all: $(DIR)/prog.bpf.o $(DIR)/prog

$(DIR)/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(DIR)/prog.bpf.o: $(DIR)/prog.bpf.c $(DIR)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -I$(DIR) -c $< -o $@

$(DIR)/prog: $(DIR)/prog.c
	$(CC) $(CFLAGS) $< -o $@ -lbpf -lelf -lz

clean:
	find challenges -name 'prog.bpf.o' -delete
	find challenges -name 'prog' -type f -delete
	find challenges -name 'vmlinux.h' -delete
