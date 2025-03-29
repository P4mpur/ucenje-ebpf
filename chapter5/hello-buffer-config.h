#ifndef HELLO_BUFFER_CONFIG_H
#define HELLO_BUFFER_CONFIG_H


//#include <linux/types.h>



#define TASK_COMM_LEN 16
#define ARGV_LEN 128
#define FILENAME_LEN 512

struct event_t {
    int pid;
    int ppid;
    int uid;
    char comm[TASK_COMM_LEN];
    char filename[ARGV_LEN];
    char argv[ARGV_LEN];
    int argv_size;
};




#endif

//void traverse_to_root(struct data_t *process,int level) {
//    char path[40];
//    int fd;
//    printf("Tracing process hierarchy:\n");
//
//    struct data_t *current_process = process;
//
//    while (current_process != NULL) {
//
//   snprintf(path, sizeof(path), "/proc/%d/cmdline", current_process->pid);
//
//   FILE *cmdline_file = fopen(path, "rb");
//   if (cmdline_file) {
//       char buffer[4096];
//       size_t len = fread(buffer, 1, sizeof(buffer) - 1, cmdline_file);
//       if (len == 0) {
//           if (ferror(cmdline_file)) {
//               perror("Error reading cmdline file");
//           } else if (feof(cmdline_file)) {
//               printf("Reached end of cmdline file unexpectedly\n");
//           }
//       } else {
//           buffer[len] = '\0'; // Null-terminate the buffer
//           // Process the buffer as needed
//       }
//       fclose(cmdline_file);
//   } else {
//       perror("Failed to open cmdline file");
//   }
//
//   char buffer[4096];
//   size_t len = fread(buffer, 1, sizeof(buffer) - 1, cmdline_file);
//   printf("len is %ld\n", len);
//   if (len == 0 && ferror(cmdline_file)) {
//       perror("Failed to read cmdline file");
//       fclose(cmdline_file);
//       return;
//   }
//   buffer[len] = '\0';  // Null-terminate the buffer
//
//   for (size_t i = 0; i < len; i++) {
//    if (buffer[i] == '\0') {
//        buffer[i] = ' ';
//    }
//   }
//
//   current_process->cmdline = malloc(len + 1);
//   if (!current_process->cmdline) {
//       perror("Failed to allocate memory for cmdline");
//       fclose(cmdline_file);
//       return;
//   }
//   strncpy(current_process->cmdline, buffer, len + 1);
//
//    // Print process information
//    printf("↪ %-6d %-6d %-16s Parent: %-16s %s\n",
//           current_process->pid,
//           current_process->ppid,
//           current_process->command,
//           current_process->parent_com,
//           current_process->cmdline ? current_process->cmdline : "");
//
//        // If the current process is the root (e.g., PID 1), stop the traversal
//        if (current_process->pid == 1) {
//            break;
//        }
//         level++;
//
//        // Retrieve the parent process information
//        current_process = get_process_info(current_process->ppid);
//    }
//}
