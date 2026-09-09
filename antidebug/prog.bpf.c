// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define SIGKILL 9

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe")
int handle_hook(void *ctx)
{
    struct task_struct *task;
    struct task_struct *parent;
    char comm[16] = {};
    char parent_comm[16] = {};

    task = (struct task_struct *)bpf_get_current_task_btf();
    if (!task)
        return 0;

    parent = BPF_CORE_READ(task, real_parent);
    if (!parent)
        return 0;

    /* Get the command name of the current process and its parent process. */
    if (bpf_get_current_comm(comm, sizeof(comm)) != 0)
        return 0;

    /* Get the command name of the parent process. */
    bpf_probe_read_kernel_str(parent_comm, sizeof(parent_comm), parent->comm);

    if (__builtin_memcmp(parent_comm, "gdb", 4) == 0)
    {
        bpf_send_signal(SIGKILL);
    }

    return 0;
}