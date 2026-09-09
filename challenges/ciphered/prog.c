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

// You need to modify this program to add the --shift argument.
int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int err;
    int shift = 3; // Default shift value
    int opt;

    static struct option long_options[] = {
        {"shift", required_argument, 0, 's'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "s:", long_options, NULL)) != -1)
    {
        switch (opt)
        {
        case 's':
            shift = atoi(optarg);
            break;
        default:
            fprintf(stderr, "Usage: %s [--shift N]\n", argv[0]);
            return 1;
        }
    }

    shift %= 26; // Ensure shift is within the alphabet range
    if (shift < 0)
        shift += 26; // Handle negative shifts

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

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "values");
    __u32 key = 0;
    __u64 val = shift;
    err = bpf_map__update_elem(map, &key, sizeof(key), &val, sizeof(val), BPF_ANY);
    if (err)
    {
        fprintf(stderr, "bpf_map__update_elem failed: %d\n", err);
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
