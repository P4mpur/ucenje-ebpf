#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <pwd.h>
#include <fcntl.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include "logger.h"
#include "hello-buffer-config.skel.h"
#include "hello-buffer-config.h"

#include <signal.h>

#include <bpf/bpf.h>

void get_user_info(int uid)
{
    struct passwd *pwd = getpwuid(uid);
    if (pwd) {
       LOGI("User: %s", pwd->pw_name);
    } else {
       LOGI("User ID %d not found", uid);
    }
}

struct process_t* get_process_info(int pid) {
    static struct process_t proc;
    char line[256], path[128];
    FILE *status_file;

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    status_file = fopen(path, "r");
    if (!status_file) return NULL;

    memset(&proc, 0, sizeof(proc));

   while (fgets(line, sizeof(line), status_file)) {
    if (strncmp(line, "Name:", 5) == 0)
        sscanf(line + 6, "%255s", proc.command);
    else if (strncmp(line, "Pid:", 4) == 0)
        sscanf(line + 5, "%d", &proc.pid);
    else if (strncmp(line, "PPid:", 5) == 0)
        sscanf(line + 6, "%d", &proc.ppid);
    else if (strncmp(line, "Uid:", 4) == 0)
        sscanf(line + 5, "%d", &proc.uid);  // ✅ extract real UID
   }
   
    fclose(status_file);

    snprintf(path, sizeof(path), "/proc/%d/comm", proc.ppid);
    FILE *comm_file = fopen(path, "r");
    if (comm_file) {
        fgets(proc.parent_com, sizeof(proc.parent_com), comm_file);
        proc.parent_com[strcspn(proc.parent_com, "\n")] = '\0';
        fclose(comm_file);
    } else {
        strncpy(proc.parent_com, "unknown", sizeof(proc.parent_com) - 1);
    }

    return &proc;
}

void traverse_to_root(struct process_t *process) {
    char block[4096] = "";
    char line[512];
    struct process_t *current = process;

    strcat(block, "");

    while (current && current->pid != 1) {
        snprintf(line, sizeof(line),
                 "↪ UID: %-4d PID: %-6d PPID: %-6d CMD: %-16s Parent: %-16s ",
                 current->uid, current->pid, current->ppid, current->command, current->parent_com);
        strcat(block, line);

        struct passwd *pwd = getpwuid(current->uid);
        snprintf(line, sizeof(line), "   User: %s\n", pwd ? pwd->pw_name : "unknown");
        strcat(block, line);

        current = get_process_info(current->ppid);
    }

    if (current && current->pid == 1) {
        snprintf(line, sizeof(line),
                 "↪ UID: %-4d PID: %-6d PPID: %-6d CMD: %-16s Parent: %-16s ",
                 current->uid, current->pid, current->ppid, current->command, current->parent_com);
        strcat(block, line);

        struct passwd *pwd = getpwuid(current->uid);
        snprintf(line, sizeof(line), "   User: %s\n", pwd ? pwd->pw_name : "unknown");
        strcat(block, line);
    }

    log_block(LOG_INFO, "Tracing process hierarchy:", block);
}


int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event_t *event = data;
    get_user_info(event->uid);
    char argv_buf[ARGV_LEN + 1] = {};

    if (event->argv_size > 0) {
        memcpy(argv_buf, event->argv, event->argv_size);
        argv_buf[event->argv_size] = '\0';

        // Replace nulls with spaces for readability
        for (int i = 0; i < event->argv_size; i++) {
            if (argv_buf[i] == '\0') argv_buf[i] = ' ';
        }
    }

   LOGI("PID: %d, PPID: %d, UID: %d, Command: %s, Filename: %s, ARGV %s",
           event->pid, event->ppid, event->uid, event->comm, event->filename, argv_buf);


    struct process_t *start = get_process_info(event->pid);
    if (start) traverse_to_root(start);


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

    // Initialize logging: use_syslog = 1, log_file = "/tmp/my-ebpf.log"
    log_init("ebpf-tracer", 1, "/tmp/my-ebpf.log");
    log_set_level(LOG_DEBUG);  // optional, for verbose logging

    libbpf_set_print(libbpf_print_fn);

    skel = hello_buffer_config_bpf__open_and_load();
    if (!skel) {
        LOGE("Failed to open BPF skeleton");
        return 1;
    }

    err = hello_buffer_config_bpf__attach(skel);
    if (err) {
        LOGE("Failed to attach BPF programs: %d", err);
        hello_buffer_config_bpf__destroy(skel);
        return 1;
    }

    LOGI("BPF programs attached successfully");

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        LOGE("Failed to create ring buffer");
        hello_buffer_config_bpf__destroy(skel);
        return 1;
    }

    // Main event loop
    while (1) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            LOGI("Interrupted by user, exiting.");
            break;
        } else if (err < 0) {
            LOGE("Error polling ring buffer: %d", err);
            break;
        }
    }

    ring_buffer__free(rb);
    hello_buffer_config_bpf__destroy(skel);
    log_close();
    return 0;
}

