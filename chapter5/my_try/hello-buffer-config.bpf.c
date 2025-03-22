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
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct data_t);
} my_config SEC(".maps");

SEC("ksyscall/execve")
int BPF_KPROBE_SYSCALL(hello, const char *pathname)
{
   struct data_t data = {}; 
   struct user_msg_t *p;
   // Define task_struct to get ppid and parent "name"
   struct task_struct *task;

   // get parent pid and parent "name"
   task = (struct task_struct*)bpf_get_current_task_btf();
   if(!task) return 0;

   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   bpf_get_current_comm(&data.command, sizeof(data.command));
   bpf_probe_read_user_str(&data.path, sizeof(data.path), pathname);

   // pid_t parent_pid = task->real_parent->tgid;
   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data, sizeof(data));   
   //bpf_map_update_elem(&my_config, &data.pid,&data,BPF_ANY);
   return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
