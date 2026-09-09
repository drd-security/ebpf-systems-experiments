#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAX_TS 10000

/* Same structure as in prog.bpf.c */
struct pff_event
{
    __u32 pid;
    __u32 type;
    __u64 ts_ns;
};

static volatile int running = 1;

/* Configuration derived from command-line arguments. */
static __u64 lower_count = 0;
static __u64 upper_count = 0;
static __u64 window_ns = 0;

/* State for the single monitored process
 * (we monitor only one instance of page_fault_gen at a time)
 */
static __u32 monitored_pid = 0;
static __u64 first_fault_ts = 0;

/* Timestamp queue:
 * We keep a circular buffer of recent page-fault timestamps.
 */
static __u64 ts_queue[MAX_TS];
static __u32 queue_capacity = MAX_TS;
static __u32 head = 0;  /* Index of the oldest timestamp */
static __u32 count = 0; /* Number of valid timestamps currently stored */

static int high_reported = 0;
static int low_reported = 0;

/* Earliest future instant when the PFF may become too low.
 * 0 means that no future low-bound check is currently scheduled.
 */
static __u64 next_low_deadline_ns = 0;

static void handle_sig(int sig)
{
    (void)sig;
    running = 0;
}

/* Current CLOCK_MONOTONIC time in nanoseconds
 * (same clock as bpf_ktime_get_ns).
 */
static unsigned long long now_ns(void)
{
    struct timespec tp;
    clock_gettime(CLOCK_MONOTONIC, &tp);
    return (unsigned long long)tp.tv_sec * 1000000000ULL + (unsigned long long)tp.tv_nsec;
}

/* Remove timestamps that are older than the current sliding window.
 *
 * A timestamp is expired if:
 *     now - ts > window_ns
 */
static void evict_old(__u64 now)
{
    while (count > 0)
    {
        __u64 oldest = ts_queue[head];

        if (now - oldest > window_ns)
        {
            head = (head + 1) % queue_capacity; // Move head to the next timestamp
            count--;
        }
        else
        {
            break;
        }
    }
}

/* Insert a new page-fault timestamp into the circular queue. */
static int push_ts(__u64 ts)
{
    __u32 tail;

    /* Before inserting the new timestamp, evict older ones. */
    evict_old(ts);

    if (count == queue_capacity)
    {
        head = (head + 1) % queue_capacity;
        count--;
    }

    tail = (head + count) % queue_capacity;
    ts_queue[tail] = ts;
    count++;

    return 0;
}

/* Recompute the earliest future instant when the PFF may become too low.
 *
 * We do not want to check the lower bound periodically.
 * Instead, we compute the first timestamp expiration that could make the
 * number of faults in the window drop below lower_count.
 */
static void recompute_next_low_deadline(__u64 now)
{
    if (monitored_pid == 0 || first_fault_ts == 0)
    {
        next_low_deadline_ns = 0;
        return;
    }

    /* Do not evaluate "too low" before one full time window has elapsed
     * since the first observed page fault.
     */
    if (now - first_fault_ts < window_ns)
    {
        next_low_deadline_ns = first_fault_ts + window_ns + 1;
        return;
    }

    /* Keep the queue up to date for the current time. */
    evict_old(now);

    /* If we are already below lower_count, there is no future deadline
     * to wait for. A new event will recompute the deadline later.
     */
    if ((__u64)count < lower_count)
    {
        next_low_deadline_ns = 0;
        return;
    }

    /* Count is at least lower_count here.
     * The critical timestamp is the one whose expiration would make the
     * count drop below lower_count.
     */
    {
        __u32 critical_pos = (__u32)((__u64)count - lower_count);
        __u32 critical_idx = (head + critical_pos) % queue_capacity;
        __u64 critical_ts = ts_queue[critical_idx];

        next_low_deadline_ns = critical_ts + window_ns + 1;
    }
}

/* Callback called by libbpf for each perf event received from the kernel.
 *
 * For every page fault:
 *   1. Initialize the monitored PID if needed
 *   2. Ignore events from other PIDs
 *   3. Insert the timestamp into the sliding window
 *   4. Check the upper bound immediately
 */
static void on_event(void *ctx, int cpu, void *data, __u32 size)
{
    struct pff_event *e = data;

    (void)ctx;
    (void)cpu;
    (void)size;

    /* First observed event: start monitoring this PID. */
    if (monitored_pid == 0)
    {
        monitored_pid = e->pid;
        first_fault_ts = e->ts_ns;
    }

    /* Ignore any other process
     * (challenge guarantees one instance only).
     */
    if (e->pid != monitored_pid)
        return;

    if (push_ts(e->ts_ns) != 0)
    {
        fprintf(stderr, "Failed to store page-fault timestamp\n");
        return;
    }

    /* If the BPF side detected too high, print it at least once. */
    if (e->type == 1)
    {
        if (!high_reported)
        {
            printf("PFF too high for process with PID %u\n", monitored_pid);
            fflush(stdout);
            high_reported = 1;
        }
    }
    else
    {
        /* The current fault did not trigger too high. */
        high_reported = 0;
    }

    /* If we are back above the lower bound, reset the low anti-spam flag. */
    if ((__u64)count >= lower_count)
        low_reported = 0;

    /* Recompute the earliest future instant when "too low" may become true. */
    recompute_next_low_deadline(e->ts_ns);
}

/* Callback used when perf events are lost. */
static void on_lost(void *ctx, int cpu, __u64 lost_cnt)
{
    (void)ctx;
    fprintf(stderr, "Lost %llu events on CPU %d\n",
            (unsigned long long)lost_cnt, cpu);
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    struct perf_buffer *pb;
    struct bpf_map *map;
    int err;

    int upper_bound_freq_ms = 100; /* Default from the statement */
    int lower_bound_freq_ms = 10;  /* Default from the statement */
    int time_window_ms = 50;       /* Default from the statement */

    int opt;

    static struct option long_options[] = {
        {"upper_bound_freq_ms", required_argument, 0, 'u'},
        {"lower_bound_freq_ms", required_argument, 0, 'l'},
        {"time_window_ms", required_argument, 0, 'w'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "u:l:w:", long_options, NULL)) != -1)
    {
        switch (opt)
        {
        case 'u':
            upper_bound_freq_ms = atoi(optarg);
            break;
        case 'l':
            lower_bound_freq_ms = atoi(optarg);
            break;
        case 'w':
            time_window_ms = atoi(optarg);
            break;
        default:
            fprintf(stderr,
                    "Usage: %s [--upper_bound_freq_ms N] [--lower_bound_freq_ms N] [--time_window_ms N]\n",
                    argv[0]);
            return 1;
        }
    }

    /* Basic input sanitization. */
    if (upper_bound_freq_ms < 1)
        upper_bound_freq_ms = 1;
    if (lower_bound_freq_ms < 1)
        lower_bound_freq_ms = 1;
    if (time_window_ms < 1)
        time_window_ms = 1;

    /* Convert frequencies into counts for the sliding window. */
    upper_count = (__u64)upper_bound_freq_ms * (__u64)time_window_ms;
    lower_count = (__u64)lower_bound_freq_ms * (__u64)time_window_ms;
    window_ns = (__u64)time_window_ms * 1000000ULL;

    /* The statement guarantees:
     *   upper_bound_freq_ms * time_window_ms <= 10000
     * We use MAX_TS = 10000 as a safe fixed capacity for the user-space queue.
     */
    if (upper_count > MAX_TS)
    {
        fprintf(stderr,
                "Invalid configuration: upper_bound_freq_ms * time_window_ms must be <= %d\n", MAX_TS);
        return 1;
    }

    if (lower_count > upper_count)
    {
        fprintf(stderr,
                "Invalid configuration: lower bound must be <= upper bound\n");
        return 1;
    }

    /* Open the compiled BPF object file. */
    obj = bpf_object__open_file("prog.bpf.o", NULL);
    if (!obj)
    {
        perror("bpf_object__open_file");
        return 1;
    }

    /* Load the BPF program into the kernel. */
    err = bpf_object__load(obj);
    if (err)
    {
        perror("bpf_object__load");
        bpf_object__close(obj);
        return 1;
    }

    /* Initialize the config map with the parameters for the BPF program. */
    map = bpf_object__find_map_by_name(obj, "config_map");
    if (!map)
    {
        fprintf(stderr, "config_map not found\n");
        bpf_object__close(obj);
        return 1;
    }

    __u32 key0 = 0, key1 = 1, key2 = 2;

    err = bpf_map__update_elem(map, &key0, sizeof(key0),
                               &lower_count, sizeof(lower_count), BPF_ANY);
    if (err)
    {
        fprintf(stderr, "update lower_count failed: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    err = bpf_map__update_elem(map, &key1, sizeof(key1),
                               &upper_count, sizeof(upper_count), BPF_ANY);
    if (err)
    {
        fprintf(stderr, "update upper_count failed: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }
    err = bpf_map__update_elem(map, &key2, sizeof(key2),
                               &window_ns, sizeof(window_ns), BPF_ANY);
    if (err)
    {
        fprintf(stderr, "update window_ns failed: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    /* Find the BPF program by name. */
    prog = bpf_object__find_program_by_name(obj, "handle_hook");
    if (!prog)
    {
        fprintf(stderr, "program not found\n");
        bpf_object__close(obj);
        return 1;
    }

    /* Attach the kprobe program. */
    link = bpf_program__attach(prog);
    if (!link)
    {
        perror("bpf_program__attach");
        bpf_object__close(obj);
        return 1;
    }

    /* Find the perf-event map used for kernel -> user-space events. */
    int events_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (events_fd < 0)
    {
        fprintf(stderr, "events map not found\n");
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    /* Create the perf buffer. */
    pb = perf_buffer__new(events_fd, 8, on_event, on_lost, NULL, NULL);
    if (!pb)
    {
        fprintf(stderr, "perf_buffer__new failed\n");
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    printf("PFF monitor: lower=%d, upper=%d, window=%dms\n",
           lower_bound_freq_ms, upper_bound_freq_ms, time_window_ms);
    printf("Monitoring started (filtering by process name). Press Ctrl+C to stop.\n");
    fflush(stdout);

    /* Main loop:
     *   - wait for perf events
     *   - wake up exactly when the lower bound may become false
     * This avoids periodic checks every fixed 10 ms.
     */
    while (running)
    {
        __u64 now = now_ns();
        int timeout_ms = 1000; /* Default wait time when no deadline is scheduled. */

        /* If a future low-bound deadline is known, compute the exact timeout
         * until that instant instead of polling periodically.
         */
        if (next_low_deadline_ns != 0)
        {
            if (now >= next_low_deadline_ns)
            {
                timeout_ms = 0;
            }
            else
            {
                __u64 delta_ns = next_low_deadline_ns - now;

                timeout_ms = (int)(delta_ns / 1000000ULL);

                /* Avoid busy looping when the remaining time is very small. */
                if (timeout_ms <= 0)
                    timeout_ms = 1;

                /* Keep a reasonable upper bound on the blocking time. */
                if (timeout_ms > 1000)
                    timeout_ms = 1000;
            }
        }

        err = perf_buffer__poll(pb, timeout_ms);
        if (err < 0 && err != -EINTR)
        {
            fprintf(stderr, "perf_buffer__poll error: %d\n", err);
            break;
        }

        now = now_ns();

        /* If the scheduled deadline has been reached, check the lower bound now.
         * This check is only done when it may actually become necessary.
         */
        if (next_low_deadline_ns != 0 && now >= next_low_deadline_ns)
        {
            /* Time keeps moving forward even if no page fault occurs,
             * so we must evict expired timestamps here as well.
             */
            evict_old(now);

            /* Do not print "too low" before one full time window has elapsed
             * since the first observed page fault.
             */
            if (monitored_pid != 0 &&
                first_fault_ts != 0 &&
                now - first_fault_ts >= window_ns)
            {
                /* Lower-bound check:
                 * if the number of faults currently in the window is below lower_count,
                 * report "too low".
                 */
                if ((__u64)count < lower_count)
                {
                    if (!low_reported)
                    {
                        printf("PFF too low for process with PID %u\n", monitored_pid);
                        fflush(stdout);
                        low_reported = 1;
                    }
                }
                else
                {
                    low_reported = 0;
                }
            }

            /* Compute the next possible instant when "too low" could happen again. */
            recompute_next_low_deadline(now);
        }
    }

    /* Cleanup */
    perf_buffer__free(pb);
    bpf_link__destroy(link);
    bpf_object__close(obj);

    return 0;
}