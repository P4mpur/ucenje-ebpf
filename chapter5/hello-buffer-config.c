//#include <stdio.h>
//#include <unistd.h>
//#include <errno.h>
//#include <bpf/libbpf.h>
//#include "hello-buffer-config.h"
//#include "hello-buffer-config.skel.h"

#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "hello-buffer-config.h"
#include "hello-buffer-config.skel.h"
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
#include <linux/types.h>
#include "logger.h"

typedef uint32_t u32;

// Structure which helps us have every process in one place
struct {
    const char *field_name;
    size_t offset;
    const char *format;
} fields[] = {
    {"Name:", offsetof(struct data_t, command), "%15s"},
    {"Pid:", offsetof(struct data_t, pid), "%d"},
    {"PPid:", offsetof(struct data_t, ppid), "%d"},
    {"Uid:", offsetof(struct data_t, uid), "%d"},
    // Add more fields as needed
};


// So basically it's set that libbpf_set_print uses this function for printing
// But it's more for libbpf logs than it's for "logs" that we're creating
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

struct data_t* get_process_info(int pid) {
    static struct data_t proc;
    char path[40], buffer[128];
    FILE *status_file, *cmdline_file;
    char parent_comm[16];

//   if (proc.cmdline)
//   {
//      free(proc.cmdline);
//      proc.cmdline = NULL;
//   }

    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    status_file = fopen(path, "r");
    if (!status_file) {
        return NULL;
    }

   // This is where the struct comes in handy, i don't need to have many if else's
   while (fgets(buffer, sizeof(buffer), status_file)) {
       for (int i = 0; i < sizeof(fields)/sizeof(fields[0]); i++) {
           if (strncmp(buffer, fields[i].field_name, strlen(fields[i].field_name)) == 0) {
               void *field_ptr = (char *)&proc + fields[i].offset;
               sscanf(buffer + strlen(fields[i].field_name) + 1, fields[i].format, field_ptr);
               break;
           }
       }
   }

    fclose(status_file);

   // PAzi sad ce uzmes celu komandu bajco
   snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
   cmdline_file = fopen(path,"r");
   if (cmdline_file) {
      cmdline_file = fopen(path,"r");
      fseek(cmdline_file, 0, SEEK_END);
      int len = ftell(cmdline_file);
      fseek(cmdline_file, 0, SEEK_SET);

      if (len>0)
      {
         // Allocate memory for cmdline
         if (proc.cmdline){
            fread(proc.cmdline, 1, len, cmdline_file);
            for (long i = 0; i< len; i++)
            {
               if(proc.cmdline[i]=='\0')
                  proc.cmdline[i] = ' ';
            }
            proc.cmdline[len] = '\0';
         }
      }
      fclose(cmdline_file);
   }



    // Retrieve parent process command
    snprintf(path, sizeof(path), "/proc/%d/comm", proc.ppid);
    status_file = fopen(path, "r");
    if (status_file) {
        if (fgets(parent_comm, sizeof(parent_comm), status_file)) {
            // Remove newline character
            parent_comm[strcspn(parent_comm, "\n")] = '\0';
            strncpy(proc.parent_com, parent_comm, sizeof(proc.parent_com) - 1);
            proc.parent_com[sizeof(proc.parent_com) - 1] = '\0';
        }
        fclose(status_file);
    } else {
        strncpy(proc.parent_com, "Unknown", sizeof(proc.parent_com) - 1);
        proc.parent_com[sizeof(proc.parent_com) - 1] = '\0';
    }

    return &proc;
}

void traverse_to_root(struct data_t *process,int level) {
    printf("Tracing process hierarchy:\n");

    struct data_t *current_process = process;

    while (current_process != NULL) {

    // Print process information
    printf("↪ %-6d %-6d %-16s Parent: %-16s %s\n",
           current_process->pid,
           current_process->ppid,
           current_process->command,
           current_process->parent_com,
           current_process->cmdline ? current_process->cmdline : "");

        // If the current process is the root (e.g., PID 1), stop the traversal
        if (current_process->pid == 1) {
            break;
        }
         level++;

        // Retrieve the parent process information
        current_process = get_process_info(current_process->ppid);
    }
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
    struct data_t *m = data;

    printf("Event received on CPU %d:\n", cpu);
    printf("%-6d %-6d %-16s %-16s %s %s\n",
           m->pid, m->uid, m->command, m->path, m->message, m->cmdline);
    printf("PPID: %d, Parent Command: %-16s Full Command: %s\n",
           m->ppid, m->parent_com,m->cmdline);

    // Traverse and display the process hierarchy to the root
   traverse_to_root(m,0);
}

void preload_processes(int map_fd, struct bpf_map *map) {
    DIR *dir = opendir("/proc");
    struct dirent *entry;
    if (!dir) {
        perror("Failed to open /proc");
        return;
    }

    printf("[+] Preloading existing processes...\n");

    while ((entry = readdir(dir)) != NULL) {
        if (!isdigit(entry->d_name[0])) continue;  // Ignore non-numeric entries (not PIDs)

        int pid = atoi(entry->d_name);
        char stat_path[64];
        snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);

        FILE *stat_file = fopen(stat_path, "r");
        if (!stat_file) continue;

        struct data_t process = {};
        char comm[16], state;
        int ppid;

        if (fscanf(stat_file, "%d %s %c %d", &process.pid, comm, &state, &ppid) == 4) {
            process.ppid = ppid;
            strncpy(process.command, comm, sizeof(process.command) - 1);

            // Get UID from /proc/[pid]/status
            char status_path[64];
            snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
            FILE *status_file = fopen(status_path, "r");
            if (status_file) {
                char line[256];
                while (fgets(line, sizeof(line), status_file)) {
                    if (strncmp(line, "Uid:", 4) == 0) {
                        sscanf(line, "Uid:\t%d", &process.uid);
                        break;
                    }
                }
                fclose(status_file);
            }

            // Lookup parent command
            snprintf(stat_path, sizeof(stat_path), "/proc/%d/comm", ppid);
            FILE *parent_file = fopen(stat_path, "r");
            if (parent_file) {
                fgets(process.parent_com, sizeof(process.parent_com), parent_file);
                fclose(parent_file);
            } else {
                strncpy(process.parent_com, "unknown", sizeof(process.parent_com) - 1);
            }

            // Insert into BPF map
            printf("Process PID before inserting: %d\n", process.pid);
            printf("map_fd, makes sense? - %d\n", map_fd);
            printf("SIZIEIEIEIEIEIE : %d", (int)sizeof(process));
            uint32_t u32_pid = process.pid;
            
            if (bpf_map_update_elem(map_fd, &u32_pid, &process, BPF_ANY) == 0) {
                printf("  [+] Loaded: PID=%d PPID=%d CMD=%s Parent=%s\n",
                        process.pid, process.ppid, process.command, process.parent_com);
            } else {
                perror("  [-] Failed to insert process");  // 🔥 Print exact error
                printf("  [-] Failed to insert PID=%d\n", process.pid);
            }

        }
        fclose(stat_file);
    }

    closedir(dir);
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
	printf("Izgubi ga bate\n");
   return;
}

int main()
{
    struct hello_buffer_config_bpf *skel;
    int err;
	struct perf_buffer *pb = NULL;

	libbpf_set_print(libbpf_print_fn);

	skel = hello_buffer_config_bpf__open_and_load();
	if (!skel) {
		printf("Failed to open BPF object\n");
		return 1;
	}

	err = hello_buffer_config_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		hello_buffer_config_bpf__destroy(skel);
        return 1;
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);
	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		hello_buffer_config_bpf__destroy(skel);
        return 1;
	}

  preload_processes(bpf_map__fd(skel->maps.my_config),skel->maps.my_config);


	while (true) {
		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

	perf_buffer__free(pb);
	hello_buffer_config_bpf__destroy(skel);
	return -err;
}
