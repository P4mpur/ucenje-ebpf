#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

struct event_t {
    u32 pid;
    u32 uid;
    char comm[16];       // Process name
    char filename[256];  // Executed program path
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(struct trace_event_raw_sys_enter *ctx) {
    struct event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;  // Get PID
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;  // Get user ID

    // Get process name
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    // Get executed program path (first argument of execve)
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), filename);

    // Send event to user-space
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
