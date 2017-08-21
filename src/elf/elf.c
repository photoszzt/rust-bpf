#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <sys/socket.h>
#include <linux/unistd.h>
#include "../../bpf.h"
#include <poll.h>
#include <linux/perf_event.h>
#include <sys/resource.h>
#include "elf.h"

extern int bpf_pin_object(int fd, const char *pathname);
__u64 ptr_to_u64(void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

void bpf_apply_relocation(int fd, struct bpf_insn *insn)
{
	insn->src_reg = BPF_PSEUDO_MAP_FD;
	insn->imm = fd;
}

int bpf_create_map(enum bpf_map_type map_type, int key_size,
	int value_size, int max_entries)
{
	int ret;
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_type = map_type;
	attr.key_size = key_size;
	attr.value_size = value_size;
	attr.max_entries = max_entries;
	ret = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
	if (ret < 0 && errno == EPERM) {
		// When EPERM is returned, two reasons are possible:
		// 1. user has no permissions for bpf()
		// 2. user has insufficent rlimit for locked memory
		// Unfortunately, there is no api to inspect the current usage of locked
		// mem for the user, so an accurate calculation of how much memory to lock
		// for this new program is difficult to calculate. As a hack, bump the limit
		// to unlimited. If program load fails again, return the error.
		struct rlimit rl = {};
		if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
			rl.rlim_max = RLIM_INFINITY;
			rl.rlim_cur = rl.rlim_max;
			if (setrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
				ret = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
			}
			else {
				printf("setrlimit() failed with errno=%d\n", errno);
				return -1;
			}
		}
	}
	return ret;
}

static void create_bpf_obj_get(const char *pathname, void *attr)
{
	union bpf_attr *ptr_bpf_attr;
	ptr_bpf_attr = (union bpf_attr *)attr;
	ptr_bpf_attr->pathname = ptr_to_u64((void *) pathname);
}

static int get_pinned_obj_fd(const char *path)
{
	union bpf_attr attr = {};
	create_bpf_obj_get(path, &attr);
	return syscall(__NR_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

bpf_map *bpf_load_map(bpf_map_def *map_def, const char *path)
{
	bpf_map *map;
	struct stat st;
	int ret, do_pin = 0;
	map = calloc(1, sizeof(bpf_map));
	if (map == NULL)
		return NULL;
	memcpy(&map->def, map_def, sizeof(bpf_map_def));
	switch (map_def->pinning) {
	case 1: // PIN_OBJECT_NS
		// TODO to be implemented
		return 0;
	case 2: // PIN_GLOBAL_NS
		if (stat(path, &st) == 0) {
			ret = get_pinned_obj_fd(path);
			if (ret < 0) {
				return 0;
			}
			map->fd = ret;
			return map;
		}
		do_pin = 1;
	}
	map->fd = bpf_create_map(map_def->type,
		map_def->key_size,
		map_def->value_size,
		map_def->max_entries
	);
	if (map->fd < 0) {
		return 0;
	}
	if (do_pin) {
		ret = bpf_pin_object(map->fd, path);
		if (ret < 0) {
			return 0;
		}
	}
	return map;
}

int bpf_prog_load(enum bpf_prog_type prog_type,
	const struct bpf_insn *insns, int prog_len,
	const char *license, int kern_version,
	char *log_buf, int log_size)
{
	int ret;
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.prog_type = prog_type;
	attr.insn_cnt = prog_len / sizeof(struct bpf_insn);
	attr.insns = ptr_to_u64((void *) insns);
	attr.license = ptr_to_u64((void *) license);
	attr.log_buf = ptr_to_u64(log_buf);
	attr.log_size = log_size;
	attr.log_level = 1;
	attr.kern_version = kern_version;
	ret = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (ret < 0 && errno == EPERM) {
		// When EPERM is returned, two reasons are possible:
		// 1. user has no permissions for bpf()
		// 2. user has insufficent rlimit for locked memory
		// Unfortunately, there is no api to inspect the current usage of locked
		// mem for the user, so an accurate calculation of how much memory to lock
		// for this new program is difficult to calculate. As a hack, bump the limit
		// to unlimited. If program load fails again, return the error.
		struct rlimit rl = {};
		if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
			rl.rlim_max = RLIM_INFINITY;
			rl.rlim_cur = rl.rlim_max;
			if (setrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
				ret = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
			}
			else {
				printf("setrlimit() failed with errno=%d\n", errno);
				return -1;
			}
		}
	}
	return ret;
}

int bpf_update_element(int fd, void *key, void *value, unsigned long long flags)
{
	union bpf_attr attr = {
		.map_fd = fd,
		.key = ptr_to_u64(key),
		.value = ptr_to_u64(value),
		.flags = flags,
	};
	return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}
int perf_event_open_map(int pid, int cpu, int group_fd, unsigned long flags)
{
	struct perf_event_attr attr = {0,};
	attr.type = PERF_TYPE_SOFTWARE;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.wakeup_events = 1;
	attr.size = sizeof(struct perf_event_attr);
	attr.config = 10; // PERF_COUNT_SW_BPF_OUTPUT
	return syscall(__NR_perf_event_open, &attr, pid, cpu,
		       group_fd, flags);
}
