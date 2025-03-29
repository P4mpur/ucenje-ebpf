#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <pwd.h>
#include <fcntl.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdint.h>
#include "logger.h"
#include "hello-buffer-config.skel.h"
#include "hello-buffer-config.h"

#include <signal.h>

#include <bpf/bpf.h>

int handle_event(void *ctx, void *data, size_t data_sz){
    struct event_t *m = data;
    // int cpu = bpf_get_smp_processor_id(); // optional


    //printf("%-6d %-6d %-16s %-16s %s %s\n", m->ppid, m->uid, m->command, m->path, m->message, m->cmdline);
    printf("PPID: %d, PID: %d\n",
           m->ppid, m->pid);

    // Traverse and display the process hierarchy to the root
   //traverse_to_root(m,0);
   // Optionally print argv if available
    if (m->argv_size > 0) {
        char argv_buf[ARGV_LEN + 1] = {};
        memcpy(argv_buf, m->argv, m->argv_size);
        argv_buf[m->argv_size] = '\0';

        // Replace nulls with spaces for readability
        for (int i = 0; i < m->argv_size; i++) {
            if (argv_buf[i] == '\0') argv_buf[i] = ' ';
        }

        printf("    ARGV: %s\n", argv_buf);
    }

   return 0;
}


// So basically it's set that libbpf_set_print uses this function for printing
// But it's more for libbpf logs than it's for "logs" that we're creating
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
        if (level >= LIBBPF_DEBUG)
                return 0;

        return vfprintf(stderr, format, args);
}

int main() {
    struct hello_buffer_config_bpf *skel;
    int err;
    struct ring_buffer *rb = NULL;
libbpf_set_print(libbpf_print_fn); 
   // Load and verify BPF object
    skel = hello_buffer_config_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[-] Failed to open BPF skeleton\n");
        return 1;
    }

    // Attach BPF programs
    err = hello_buffer_config_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "[-] Failed to attach BPF programs: %d\n", err);
        hello_buffer_config_bpf__destroy(skel);
        return 1;
    }

    printf("[+] BPF programs attached successfully!\n");

       // Set up ring buffer handler
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[-] Failed to create ring buffer\n");
        hello_buffer_config_bpf__destroy(skel);
        return 1;
    }

    // Poll for events
    while (1) {
        err = ring_buffer__poll(rb, 100 /* ms */);
        if (err == -EINTR) {
            break; // Interrupted by Ctrl+C
        } else if (err < 0) {
            fprintf(stderr, "[-] Error polling ring buffer: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    hello_buffer_config_bpf__destroy(skel);
    return 0;
}

