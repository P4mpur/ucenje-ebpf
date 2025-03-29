#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "hello-buffer-config.h"
//#include <linux/sched.h>



char message[12] = "Hello World";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output SEC(".maps");
   

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 20480);
    __type(key, u32);
    __type(value, struct data_t);
    __uint(map_flags, 0);  // 🔥 Ensure it's writable
} my_config SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct data_t data = {};
    const char *pathname = (const char *)ctx->args[0];
    char *const *argv = (char *const *)ctx->args[1];

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    if (!task)
        return 0;

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&data.command, sizeof(data.command));
    bpf_probe_read_user_str(&data.path, sizeof(data.path), pathname);

    struct task_struct *parent = task->real_parent;
    if (parent)
    {
        data.ppid = parent->tgid;
        bpf_probe_read_kernel_str(data.parent_com, sizeof(data.parent_com), parent->comm);
    }

    // 🔥 Print first 3 argv strings
    #pragma unroll
    for (int i = 0; i < 3; i++) {
        char arg[64];
        char *ptr = NULL;

        // Read argv[i] pointer
        if (bpf_probe_read_user(&ptr, sizeof(ptr), &argv[i]) < 0 || ptr == NULL)
            break;

        // Read the actual string
        if (bpf_probe_read_user_str(arg, sizeof(arg), ptr) > 0) {
            bpf_printk("argv[%d] = %s\n", i, arg);
        }
    }

    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
    bpf_map_update_elem(&my_config, &data.pid, &data, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
