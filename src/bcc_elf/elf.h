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

#endif
