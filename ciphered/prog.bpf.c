// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} values SEC(".maps");

// Place your code here. Your program must be called "handle_hook".
SEC("tracepoint/syscalls/sys_enter_write")
int handle_hook(struct trace_event_raw_sys_enter *ctx)
{
    // Read the syscall arguments (fd, buf, count)
    int fd = ctx->args[0];
    const char *buf = (const char *)ctx->args[1];
    __u64 count = ctx->args[2];

    char comm[16] = {};
    char data[256] = {};

    __u32 key = 0;
    __u64 *map_val = bpf_map_lookup_elem(&values, &key);
    if (!map_val)
        return 0;

    if (bpf_get_current_comm(comm, sizeof(comm)) != 0)
        return 0;
    // Check if the process is "echo_test"
    if (__builtin_memcmp(comm, "echo_test", 10) != 0)
    {
        return 0; // Not the target process, allow the syscall to proceed
    }

    if (fd == 1 || fd == 2)
    {
        return 0; // Writing to stdout or stderr, allow the syscall to proceed
    }

    __u64 n64 = count;
    if (n64 > sizeof(data))
        n64 = sizeof(data);
    if (n64 == 0)
        return 0;

    int n = (__u32)n64;

    // Read the data from user space
    if (bpf_probe_read_user(data, n, buf) != 0)
    {
        return 0; // Failed to read user data, allow the syscall to proceed
    }

    __u32 s = (*map_val) % 26; // Get the shift value from the map and ensure it's within the alphabet range
    for (int i = 0; i < n; i++)
    {
        if (data[i] >= 'a' && data[i] <= 'z')
        {
            data[i] = ((data[i] - 'a' + s) % 26) + 'a'; // Shift lowercase letters
        }
        else if (data[i] >= 'A' && data[i] <= 'Z')
        {
            data[i] = ((data[i] - 'A' + s) % 26) + 'A'; // Shift uppercase letters
        }
    }
    // Write the modified data back to user space
    long ret = bpf_probe_write_user((void *)buf, data, n);
    if (ret)
        bpf_printk("write_user failed: %ld\n", ret);

    return 0; // Return 0 to allow the syscall to proceed
}
