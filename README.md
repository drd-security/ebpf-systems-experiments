# eBPF Systems Experiments

Five Linux/eBPF experiments exploring kernel instrumentation, policy enforcement, kernel/userspace communication, stateful maps, timing, and perf buffers using **libbpf**.

## Challenges

| Directory | Experiment | Main eBPF concepts |
|---|---|---|
| `antidebug/` | Detect debugging activity against a target process and terminate it. | uprobes / helper functions |
| `protected_file/` | Prevent a specific process from opening regular files for writing. | BPF LSM, CO-RE reads |
| `ciphered/` | Apply a simple Caesar-style transformation to writes. | maps, userspace-to-kernel configuration |
| `fork/` | Enforce rate limiting on rapid child-process creation. | maps, timing/state |
| `page_faults/` | Monitor page-fault frequency and report threshold violations. | maps, sliding-window timestamps, perf buffer |

## Repository structure

Each challenge contains:

```text
prog.bpf.c   Kernel-side eBPF program
prog.c       User-space loader/controller
```

## Build prerequisites

A recent Linux kernel with BTF/eBPF support, plus:

- clang/LLVM;
- libbpf development headers/libraries;
- bpftool;
- libelf and zlib development packages;
- sufficient privileges/capabilities to load the relevant BPF programs.

## Build example

```bash
make CHALLENGE=antidebug
```

The Makefile generates `vmlinux.h` from `/sys/kernel/btf/vmlinux`, compiles the BPF object, and builds the userspace loader. Exact hook support depends on the running kernel and enabled LSM/BPF features.

## What this project demonstrates

- Attaching BPF programs to different kernel/user-space events.
- Reading kernel structures through CO-RE helpers.
- Blocking operations through LSM return values.
- Sharing configuration/state via BPF maps.
- Tracking time-dependent process behavior.
- Delivering kernel events to userspace with perf buffers.
- Separating a minimal verified BPF program from a richer userspace controller.

## Academic context and contribution

Two-person operating-systems project. I completed the majority of the implementation and integration; my teammate also contributed meaningfully across the challenges.

## Safety and scope

These programs are educational operating-systems exercises intended for controlled local environments. They should be run only on systems you are authorized to instrument and where you understand the kernel hooks being installed.

## Publication status

The original course statements and generated `vmlinux.h` are not included. See [NOTICE.md](NOTICE.md).
