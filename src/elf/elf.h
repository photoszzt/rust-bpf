#ifndef __ELF_ELF_H__
#define __ELF_ELF_H__
// from https://github.com/safchain/goebpf
// Apache License, Version 2.0
#define BUF_SIZE_MAP_NS 256

typedef struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
  unsigned int map_flags;
  unsigned int pinning;
  char namespace[BUF_SIZE_MAP_NS];
} bpf_map_def;

typedef struct bpf_map {
	int         fd;
	bpf_map_def def;
} bpf_map;

void bpf_apply_relocation(int fd, struct bpf_insn *insn);

int bpf_create_map(enum bpf_map_type map_type, int key_size,
                   int value_size, int max_entries);

bpf_map *bpf_load_map(bpf_map_def *map_def, const char *path);

int bpf_prog_load(enum bpf_prog_type prog_type,
                  const struct bpf_insn *insns, int prog_len,
                  const char *license, int kern_version,
                  char *log_buf, int log_size);

int bpf_update_element(int fd, void *key, void *value, unsigned long long flags);

int perf_event_open_map(int pid, int cpu, int group_fd, unsigned long flags);
#endif
