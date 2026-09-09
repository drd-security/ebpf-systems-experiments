// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1
#define FMODE_WRITE 2

#define S_IFMT 00170000
#define S_IFREG 0100000

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("lsm/file_open")
int BPF_PROG(handle_hook, struct file *file, int ret)
{
    char comm[16] = {};
    unsigned int i_mode = 0;
    unsigned int f_mode = 0;

    if (ret != 0)
        return ret;

    if (bpf_get_current_comm(comm, sizeof(comm)) != 0)
        return 0;

    if (__builtin_memcmp(comm, "scanner", 8) != 0)
        return 0;

    i_mode = BPF_CORE_READ(file, f_inode, i_mode);  // Read i_mode to check the file type.

    // Only block regular files.
    if ((i_mode & S_IFMT) != S_IFREG) 
        return 0;

    f_mode = BPF_CORE_READ(file, f_mode); // Read f_mode to check whether the file is opened for writing.

    // Reject write access when scanner opens a regular file.
    if (f_mode & FMODE_WRITE)
    {
        bpf_printk("blocking scanner open-for-write\n");
        return -EPERM;
    }

    return 0;
}