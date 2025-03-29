#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "vmlinux.h" // Ensure you have vmlinux.h

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} output SEC(".maps");

struct user_msg_t {
   char message[12];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct user_msg_t);
} my_config SEC(".maps");

SEC("ksyscall/execve")
int BPF_KPROBE_SYSCALL(hello, const char *pathname)
{
   struct data_t data = {};
   struct user_msg_t *p;
   char message[12];

   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   if (data.uid == 0) {  // Ensure UID is never zero
       data.uid = 1;
   }

   bpf_get_current_comm(&data.command, sizeof(data.command));

   if (pathname) {  // Prevent NULL pointer dereference
       bpf_probe_read_user_str(&data.path, sizeof(data.path), pathname);
   } else {
       __builtin_memset(&data.path, 0, sizeof(data.path));  
   }

   p = bpf_map_lookup_elem(&my_config, &data.uid);
   if (p) {  // Ensure p is valid before reading from it
       bpf_probe_read_kernel_str(&data.message, sizeof(data.message), p->message);
   } else {
       __builtin_memset(&data.message, 0, sizeof(data.message));
   }

   bpf_trace_printk("Hello %d\n", data.uid);
   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));

   return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

