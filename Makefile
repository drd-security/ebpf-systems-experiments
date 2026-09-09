CHALLENGE ?= antidebug
CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool

DIR := $(CHALLENGE)
VMLINUX := $(DIR)/vmlinux.h
BPF_OBJ := $(DIR)/prog.bpf.o
USER_BIN := $(DIR)/prog
ARCH_INC ?= /usr/include/$(shell uname -m)-linux-gnu

BPF_CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_x86 -I$(DIR) -I$(ARCH_INC)
USER_CFLAGS ?= -O2 -g -Wall -Wextra
USER_LIBS ?= -lbpf -lelf -lz

.PHONY: all clean
all: $(USER_BIN)

$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(DIR)/prog.bpf.c $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_BIN): $(DIR)/prog.c $(BPF_OBJ)
	$(CC) $(USER_CFLAGS) $< -o $@ $(USER_LIBS)

clean:
	rm -f */vmlinux.h */prog.bpf.o */prog
