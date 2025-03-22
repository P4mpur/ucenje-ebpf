#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/perf_event.h>
#include <unistd.h>

struct event_t {
    u32 pid;
    u32 uid;
    char comm[16];
    char filename[256];
};

void handle_event(void *ctx, int cpu, void *data, __u32 data_size) {
    struct event_t *event = (struct event_t *)data;
    printf("User: %d | PID: %d | Command: %s | Executed: %s\n", 
           event->uid, event->pid, event->comm, event->filename);
}

int main() {
    struct perf_buffer *pb;
    int map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "events"));
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find events map\n");
        return 1;
    }

    pb = perf_buffer__new(map_fd, 8, handle_event, NULL, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer\n");
        return 1;
    }

    while (1) {
        perf_buffer__poll(pb, 1000);
    }

    return 0;
}

