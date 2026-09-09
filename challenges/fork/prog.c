#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <bpf/libbpf.h>

static volatile int running = 1;

static void handle_sig(int sig)
{
    running = 0;
}

// You need to modify this program to add the --n_process and --time_separation_sec arguments.
int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    struct bpf_map *map;
    int err;
    int n_process = 1;            // Default number of processes to monitor
    int time_separation_sec = 1;  // Default time separation in seconds
    __u64 time_separation_ns = 1; // Default time separation in nanoseconds

    int opt;

    static struct option long_options[] = {
        {"n_process", required_argument, 0, 'n'},
        {"time_separation_sec", required_argument, 0, 't'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "n:t:", long_options, NULL)) != -1)
    {
        switch (opt)
        {
        case 'n':
            n_process = atoi(optarg);
            break;
        case 't':
            time_separation_sec = atoi(optarg);
            break;
        default:
            fprintf(stderr, "Usage: %s [--n_process N] [--time_separation_sec N]\n", argv[0]);
            return 1;
        }
    }

    if (n_process < 1)
        n_process = 1; // Ensure at least one process is monitored

    if (n_process > 32)
        n_process = 32; // Limit to 32 processes to avoid map overflow

    if (time_separation_sec < 1)
        time_separation_sec = 1; // Ensure at least 1 second of separation

    time_separation_ns = (__u64)time_separation_sec * 1000000000ULL; // Convert to nanoseconds

    // Open the BPF object file (kernel compiled BPF program)
    obj = bpf_object__open_file("prog.bpf.o", NULL);
    if (!obj)
    {
        perror("bpf_object__open_file");
        return 1;
    }
    // Load the BPF object file into the kernel
    err = bpf_object__load(obj);
    if (err)
    {
        perror("bpf_object__load");
        bpf_object__close(obj); // clean up on error
        return 1;
    }

    map = bpf_object__find_map_by_name(obj, "config_map");
    if (!map)
    {
        fprintf(stderr, "map not found\n");
        bpf_object__close(obj); // clean up on error
        return 1;
    }
    __u32 key0 = 0;
    __u32 key1 = 1;
    __u64 val1 = (__u64)n_process;
    __u64 val2 = time_separation_ns;

    err = bpf_map__update_elem(map, &key0, sizeof(key0), &val1, sizeof(val1), BPF_ANY);
    if (err)
    {
        fprintf(stderr, "update config_map[0] failed: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    err = bpf_map__update_elem(map, &key1, sizeof(key1), &val2, sizeof(val2), BPF_ANY);
    if (err)
    {
        fprintf(stderr, "update config_map[1] failed: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    // Find the BPF program by name
    prog = bpf_object__find_program_by_name(obj, "handle_hook");
    if (!prog)
    {
        fprintf(stderr, "program not found\n");
        bpf_object__close(obj); // clean up on error
        return 1;
    }

    // Attach the BPF program to the appropriate hook (e.g., tracepoint, kprobe)
    link = bpf_program__attach(prog);
    if (!link)
    {
        perror("bpf_program__attach");
        bpf_object__close(obj); // clean up on error
        return 1;
    }

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    printf("Program loaded. Press Ctrl+C to exit.\n");
    // Keep the program running until interrupted
    while (running)
        sleep(1);

    // Cleanup
    bpf_link__destroy(link); // detaches the program from the hook
    bpf_object__close(obj);  // unloads and frees the BPF object

    return 0;
}
