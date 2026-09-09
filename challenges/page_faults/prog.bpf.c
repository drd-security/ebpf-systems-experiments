// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_TS 10000

/* config_map:
 *   key 0 -> lower_count
 *   key 1 -> upper_count
 *   key 2 -> window_ns
 */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} config_map SEC(".maps");

/* state_map:
 *   key 0 -> monitored_pid
 *   key 1 -> first_fault_ts
 *   key 2 -> head
 *   key 3 -> stored_count
 */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} state_map SEC(".maps");

/* timestamp_map:
 * Ring buffer of recent page-fault timestamps used by the BPF side
 * to detect the upper-bound violation ("too high").
 */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_TS);
    __type(key, __u32);
    __type(value, __u64);
} timestamp_map SEC(".maps");

/* Perf-event array used to send information to user space. */
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

/* Event sent to user space.
 *
 * pid:
 *   PID of the process that caused the page fault
 * type:
 *   0 -> normal page fault event
 *   1 -> this page fault caused a "too high" condition
 */
struct pff_event
{
    __u32 pid;
    __u32 type;
    __u64 ts_ns;
};

/* Helper used to emit one event to user space. */
static __always_inline int emit_event(struct pt_regs *ctx, __u32 pid, __u32 type, __u64 ts_ns)
{
    struct pff_event e = {
        .pid = pid,
        .type = type,
        .ts_ns = ts_ns,

    };

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

/* We hook handle_mm_fault, which is the common entry point where page-fault
 * handling begins.
 *
 * For each page fault:
 *   1. Check the process name
 *   2. Keep only page_fault_gen
 *   3. Get its PID
 *   4. Get the current monotonic timestamp
 *   5. Send the event to user space
 */
SEC("kprobe/handle_mm_fault")
int handle_hook(struct pt_regs *ctx)
{

    char comm[16] = {};
    __u32 key0 = 0, key1 = 1, key2 = 2, key3 = 3;

    __u64 *upper_count_ptr, *window_ns_ptr;
    __u64 *monitored_pid_ptr, *first_fault_ts_ptr, *head_ptr, *count_ptr;

    __u32 current_pid;
    __u64 current_ts;
    __u64 upper_count;
    __u64 window_ns;
    __u32 event_type = 0;

    /* Filter by process name. */
    if (bpf_get_current_comm(comm, sizeof(comm)) != 0)
        return 0;

    /* Only keep events from the "page_fault_gen" process. */
    if (__builtin_memcmp(comm, "page_fault_gen", sizeof("page_fault_gen")) != 0)
        return 0;

    /* read configuration */
    upper_count_ptr = bpf_map_lookup_elem(&config_map, &key1);
    window_ns_ptr = bpf_map_lookup_elem(&config_map, &key2);

    /* read state */
    monitored_pid_ptr = bpf_map_lookup_elem(&state_map, &key0);
    first_fault_ts_ptr = bpf_map_lookup_elem(&state_map, &key1);
    head_ptr = bpf_map_lookup_elem(&state_map, &key2);
    count_ptr = bpf_map_lookup_elem(&state_map, &key3);

    if (!upper_count_ptr || !window_ns_ptr ||
        !monitored_pid_ptr || !first_fault_ts_ptr || !head_ptr || !count_ptr)
        return 0;

    upper_count = *upper_count_ptr;
    window_ns = *window_ns_ptr;

    /* verify if the configuration is valid */
    if (upper_count > MAX_TS || window_ns == 0)
        return 0;

    current_pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    current_ts = bpf_ktime_get_ns();
    /* First observed event: start monitoring this PID. */
    if (*monitored_pid_ptr == 0)
    {
        *monitored_pid_ptr = current_pid;
        *first_fault_ts_ptr = current_ts;
        *head_ptr = 0;
        *count_ptr = 0;
    }
    else if (*monitored_pid_ptr != current_pid)
    {
        /* only one instance is tested at a time.Ignore any other process.*/
        return 0;
    }

    /* upper bound detection */
    if (*count_ptr < upper_count)
    {
        __u32 idx = (__u32)((*head_ptr + *count_ptr) % MAX_TS);          // calculate the index for the new timestamp
        bpf_map_update_elem(&timestamp_map, &idx, &current_ts, BPF_ANY); // insert the new timestamp into the queue
        (*count_ptr)++;
    }
    else
    {
        __u32 idx = (__u32)(*head_ptr);
        __u64 *oldest_ts_ptr = bpf_map_lookup_elem(&timestamp_map, &idx);

        if (oldest_ts_ptr)
        {
            if (current_ts - *oldest_ts_ptr <= window_ns)
                event_type = 1;

            /* Overwrite the oldest slot with the new timestamp. */
            bpf_map_update_elem(&timestamp_map, &idx, &current_ts, BPF_ANY);

            /* Move the ring head forward. */
            *head_ptr = (*head_ptr + 1) % MAX_TS;
        }
    }

    /* Send one event per page fault.
     * type = 0 => normal fault
     * type = 1 => this fault triggered "too high"
     */
    emit_event(ctx, current_pid, event_type, current_ts);
    return 0;
}