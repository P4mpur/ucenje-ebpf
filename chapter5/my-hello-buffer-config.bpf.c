#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "vmlinux.h" // Ensure you have vmlinux.h

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output SEC(".maps");

struct user_msg_t
{
    char message[12];
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct user_msg_t);
} my_config SEC(".maps");

static int probe_entry_getpeername(void *ctx, struct sockaddr_in6 *addr)
{
    __u64 id = bpf_get_current_pid_tgid();
    pid_t pid = id >> 32;
    // pid_t tid = (__u32)id;

    bpf_map_update_elem(&values, &pid, &addr, BPF_ANY);
    return 0;
};

static int probe_return_getpeername(void *ctx, int ret)
{
    __u64 id = bpf_get_current_pid_tgid();
    pid_t pid = id >> 32;
    // pid_t tid = (__u32)id;
    uid_t uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    struct sockaddr_in6 **addrpp;

    addrpp = bpf_map_lookup_elem(&values, &pid);
    if (!addrpp)
        return 0;

    struct sockaddr_in6 *addr;
    addr = *addrpp;

    struct data_t data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
    data.pid = pid;
    data.uid = uid;
    data.ret = ret;
    bpf_get_current_comm(&data.command, sizeof(data.command));
    data.type_id = 1;
    bpf_probe_read_user(&data.addr, sizeof(data.addr), addr);
    // bpf_map_update_elem(&raw_sockaddr, &pid, &data.addr, BPF_ANY);

    int res = bpf_strncmp(data.command, 8, "sshd");
    if (!res)
    {
        bpf_map_update_elem(&raw_sockaddr, &pid, &data.addr, BPF_ANY);
        bpf_map_update_elem(&raw_user, &pid, &data.uid, BPF_ANY);
        bpf_printk("Updating: %d IP: %d", pid);
        bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
    }

    return 0;
}

static int probe_entry_getsockname(void *ctx, struct sockaddr_in6 *addr)
{
    __u64 id = bpf_get_current_pid_tgid();
    pid_t pid = id >> 32;
    // pid_t tid = (__u32)id;

    bpf_map_update_elem(&values, &pid, &addr, BPF_ANY);
    return 0;
};

static int probe_return_getsockname(void *ctx, int ret)
{
    __u64 id = bpf_get_current_pid_tgid();
    pid_t pid = id >> 32;
    // pid_t tid = (__u32)id;
    uid_t uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    // struct sockaddr_in **addrpp;
    // struct sockaddr_in *addr;
    struct sockaddr_in6 **addrpp;
    struct sockaddr_in6 *addr;
    struct data_t data = {};

    addrpp = bpf_map_lookup_elem(&values, &pid);
    if (!addrpp)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);

    addr = *addrpp;
    data.pid = pid;
    data.uid = uid;
    data.ret = ret;
    bpf_get_current_comm(&data.command, sizeof(data.command));
    data.type_id = 2;
    bpf_probe_read_user(&data.addr, sizeof(data.addr), addr);
    int res = bpf_strncmp(data.command, 8, "ssh");
    if (!res)
    {
        bpf_printk("Command: %s , %s Res: %d", str1, data.command, res);
        bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));
    }

    return 0;
}

SEC("tp/syscalls/sys_enter_getpeername")
int tp_sys_enter_getpeername(struct trace_event_raw_sys_enter *ctx)
{
    // return probe_entry_getpeername(ctx, (struct sockaddr_in *)ctx->args[1]);
    return probe_entry_getpeername(ctx, (struct sockaddr_in6 *)ctx->args[1]);
}

SEC("tp/syscalls/sys_exit_getpeername")
int tp_sys_exit_getpeername(struct trace_event_raw_sys_exit *ctx)
{
    return probe_return_getpeername(ctx, (int)ctx->ret);
}

SEC("tp/syscalls/sys_enter_getsockname")
int tp_sys_enter_getsockname(struct trace_event_raw_sys_enter *ctx)
{
    // return probe_entry_getsockname(ctx, (struct sockaddr_in *)ctx->args[1]);
    return probe_entry_getsockname(ctx, (struct sockaddr_in6 *)ctx->args[1]);
}

SEC("tp/syscalls/sys_exit_getsockname")
int tp_sys_exit_getsockname(struct trace_event_raw_sys_exit *ctx)
{
    return probe_return_getsockname(ctx, (int)ctx->ret);
}

SEC("ksyscall/execve")
int BPF_KPROBE_SYSCALL(hello, const char *pathname)
{
    struct data_t data = {};
    struct user_msg_t *p;
    char message[12];

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    if (data.uid == 0)
    { // Ensure UID is never zero
        data.uid = 1;
    }

    bpf_get_current_comm(&data.command, sizeof(data.command));

    if (pathname)
    { // Prevent NULL pointer dereference
        bpf_probe_read_user_str(&data.path, sizeof(data.path), pathname);
    }
    else
    {
        __builtin_memset(&data.path, 0, sizeof(data.path));
    }

    p = bpf_map_lookup_elem(&my_config, &data.uid);
    if (p)
    { // Ensure p is valid before reading from it
        bpf_probe_read_kernel_str(&data.message, sizeof(data.message), p->message);
    }
    else
    {
        __builtin_memset(&data.message, 0, sizeof(data.message));
    }

    bpf_trace_printk("Hello %d\n", data.uid);
    bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
