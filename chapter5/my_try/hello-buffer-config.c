#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "hello-buffer-config.h"
#include "hello-buffer-config.skel.h"

// So basically it's set that libbpf_set_print uses this function for printing
// But it's more for libbpf logs than it's for "logs" that we're creating
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

//void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
//{
//	struct data_t *m = data;
//	struct data_t *parent_data;
//
//
//
//	printf("%-6d %-6d %-16s %-16s %s\n", m->pid, m->uid, m->command, m->path, m->message);
//   printf("PPID: %d, Parent Command: %-16s", m->ppid, m->parent_com);
//	printf("Cpu: %d\n",cpu);
//
//   int ppid = m->ppid;
//   while (ppid != 1) {
//      if (bpf_map_lookup_elem(map_fd, &ppid, &parent_data) == 0) {
//           printf("  ↳ Parent PID: %-6d Parent CMD: %-16s\n", parent_data->ppid, parent_data->parent_com);
//           ppid = parent_data->ppid;  // Move to next parent
//      } else {
//         break;
//      }
//   }
//
//}


void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
    struct hello_buffer_config_bpf *skel = ctx; // Get skel from perf_buffer context
    struct data_t *m = data;
    struct data_t parent_data;
    int map_fd = bpf_map__fd(skel->maps.my_config); // Reuse skel, no need to reopen
    if (map_fd < 0)
   {
      fprintf(stderr, "A BE NE VALJA TI MAP_FD");
      return;
   }

    printf("PID: %-6d UID: %-6d CMD: %-16s PPID: %-6d Parent CMD: %-16s\n",
           m->pid, m->uid, m->command, m->ppid, m->parent_com);

    printf("Cpu: %d\n", cpu);
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
