// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
// Place your code here. Your program must be called "handle_hook".

#define SIGKILL 9

/* config_map:
 *   key 0 -> n_process
 *   key 1 -> time_separation_ns
 */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} config_map SEC(".maps");

/* state_map:
 *   key 0 -> head
 *   key 1 -> count
 */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} state_map SEC(".maps");

/* timestamps for last accepted children */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u64);
} timestamp_map SEC(".maps");

/* child_pid -> 1 means "kill this child when it runs" */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} kill_set SEC(".maps");

SEC("tracepoint/syscalls/sys_exit_clone")
int handle_hook(struct trace_event_raw_sys_exit *ctx)
{
    // Read the return value of the clone syscall (the PID of the new process)
    long ret = ctx->ret;
    char comm[16] = {};

    __u32 key0 = 0, key1 = 1;
    __u64 *n_ptr, *t_ptr, *head_ptr, *count_ptr;

    if (bpf_get_current_comm(comm, sizeof(comm)) != 0)
        return 0;

    // Check if the process is "forking"
    if (__builtin_memcmp(comm, "forking", 8) != 0)
    {
        return 0; // Not the target process, allow the syscall to proceed
    }

    // Read the configuration from the map

    n_ptr = bpf_map_lookup_elem(&config_map, &key0);
    t_ptr = bpf_map_lookup_elem(&config_map, &key1);
    head_ptr = bpf_map_lookup_elem(&state_map, &key0);
    count_ptr = bpf_map_lookup_elem(&state_map, &key1);

    if (!n_ptr || !t_ptr || !head_ptr || !count_ptr)
    {
        return 0; // Configuration not found, allow the syscall to proceed
    }

    __u64 n_process = *n_ptr;
    __u64 time_separation_ns = *t_ptr;

    if (n_process < 1)
        n_process = 1;
    if (n_process > 32)
        n_process = 32;

    // If the return value is negative, it indicates an error in clone()
    if (ret < 0)
    {
        return 0; // Allow the syscall to proceed (it will fail as it normally would)
    }

    if (ret == 0)
    {
        __u32 my_pid = (__u32)(bpf_get_current_pid_tgid() >> 32);   // Get the PID of the current process (the child)
        __u32 *kill_flag = bpf_map_lookup_elem(&kill_set, &my_pid); // Check if the parent PID is in the kill set
        if (kill_flag)                                              // If the parent PID is in the kill set, it means we need to kill it
        {
            bpf_map_delete_elem(&kill_set, &my_pid); // Remove the parent PID from the kill set
            bpf_send_signal(SIGKILL);                // Send SIGKILL to the child process to kill it immediately
        }
        return 0; // Allow the syscall to proceed
    }
    if (ret > 0)
    {
        __u32 child_pid = (__u32)ret; // This is the PID of the newly created child process
        __u64 current_time = bpf_ktime_get_ns(); // Get the current time in nanoseconds

        if (*count_ptr < n_process) // If we haven't reached the max number of processes to monitor
        {
            __u32 idx = (__u32)(*count_ptr);                         // Get the current count of accepted processes
            __u64 *time = bpf_map_lookup_elem(&timestamp_map, &idx); // Get the timestamp for this index
            if (!time)
                return 0;
            *time = current_time; // Store the timestamp of this accepted fork
            (*count_ptr)++;       // Increment the count of accepted processes
            return 0;
        }
        __u32 head = (__u32)(*head_ptr);
        __u64 *oldest_ptr = bpf_map_lookup_elem(&timestamp_map, &head); // Get the timestamp of the oldest accepted fork
        if (!oldest_ptr)
            return 0;

        if (current_time - *oldest_ptr < time_separation_ns)
        {
            __u32 one = 1;
            bpf_map_update_elem(&kill_set, &child_pid, &one, BPF_ANY);
            return 0;
        }

        *oldest_ptr = current_time;
        head++;
        if (head >= n_process)
            head = 0;
        *head_ptr = head;

        return 0; // Allow the syscall to proceed
    }

    return 0;
}