#!/usr/bin/python3  
from bcc import BPF
import ctypes as ct

def parse_passwd(passwd_content, attached_kprobe):
    for line in passwd_content.splitlines():  # Iterate over each line in the content
        if line.strip() and not line.startswith('#'):  # Skip empty lines and comments
            parts = line.split(':')
            if len(parts) >= 6:  # Ensure the line has enough fields
                username = parts[0]
                print("username is ", parts[0])
                print("user_ID is ", parts[2])
                user_id = int(parts[2])  # Convert user_id to integer
                mapped_string = f"Hey {username}".encode('utf-8')  # Encode string to bytes
                attached_kprobe["config"][ct.c_int(user_id)] = ct.create_string_buffer(mapped_string)
    return attached_kprobe["config"]

def read_passwd_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()

program = r"""
struct user_msg_t {
   char message[13];
};

BPF_HASH(config, u32, struct user_msg_t);

BPF_PERF_OUTPUT(output); 

struct data_t {     
   int pid;
   int uid;
   char command[16];
   char message[12];
};

int hello(void *ctx) {
   struct data_t data = {}; 
   struct user_msg_t *p;
   char message[12] = "Hello World";

   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   bpf_get_current_comm(&data.command, sizeof(data.command));

   p = config.lookup(&data.uid);
   if (p != 0) {
      bpf_probe_read_kernel(&data.message, sizeof(data.message), p->message);       
   } else {
      bpf_probe_read_kernel(&data.message, sizeof(data.message), message); 
   }

   output.perf_submit(ctx, &data, sizeof(data)); 
 
   return 0;
}
"""

b = BPF(text=program) 
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello")
content = read_passwd_file("/etc/passwd")
b["config"] = parse_passwd(content,b)
 

def print_event(cpu, data, size):  
   data = b["output"].event(data)
   print(f"{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")
   # Output the full command 
   try:
       with open(f"/proc/{data.pid}/cmdline","rb") as f:
           #cmdline = f.read().replace("\x00"," ")
           rawcmdline = f.read()
           print(f"Rawcmd: {rawcmdline!r}")
   except FileNotFoundError as e:
       print(f"Process {data.pid} no longer exists")

 
b["output"].open_perf_buffer(print_event) 
while True:   
   b.perf_buffer_poll()
