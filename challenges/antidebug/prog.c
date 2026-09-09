#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <stdarg.h>
#include <bpf/libbpf.h>

static volatile int running = 1;

static void handle_sig(int sig)
{
    running = 0;
}

int main(void)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    struct bpf_uprobe_opts opts;
    int err;
    char hangman_path[PATH_MAX];

    if (!realpath("../hangman/hangman", hangman_path))
    {
        perror("realpath");
        return 1;
    }

    obj = bpf_object__open_file("prog.bpf.o", NULL);
    if (!obj)
    {
        perror("bpf_object__open_file");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err)
    {
        fprintf(stderr, "bpf_object__load failed: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "handle_hook");
    if (!prog)
    {
        fprintf(stderr, "program handle_hook not found\n");
        bpf_object__close(obj);
        return 1;
    }

    memset(&opts, 0, sizeof(opts));
    opts.sz = sizeof(opts);
    opts.func_name = "make_hangman"; // The function in hangman to attach to.

    fprintf(stderr, "Attaching uprobe to %s:%s\n", hangman_path, opts.func_name);

    link = bpf_program__attach_uprobe_opts(
        prog,         // ebpf program to attach
        -1,           // pid of process to attach to, -1 for all processes
        hangman_path, // path to binary to attach to
        0,            // offset within binary to attach to, 0 if func_name is provided
        &opts         // options for uprobe attachment
    );

    if (!link)
    {
        perror("bpf_program__attach_uprobe_opts");
        bpf_object__close(obj);
        return 1;
    }

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    printf("Program loaded. Press Ctrl+C to exit.\n");

    while (running)
        sleep(1);

    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}