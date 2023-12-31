#ifdef TS_NVM_IS_NV_JEMALLOC
#define _GNU_SOURCE
#include "debug.h"
#include "makalu.h"
#include "nvm.h"
#include "port.h"
#include "util.h"
#include <assert.h>
#include <fcntl.h>
#include <jemalloc/jemalloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

ts_nvm_root_obj_t *nvm_load_heap(const char *path, size_t sz, int *is_created) {
  ts_nvm_root_obj_t *root_obj;

  /* Get a root pointer */
  *is_created = 1;
  root_obj = nv_calloc(1, sizeof(*root_obj));
  if (unlikely(!root_obj)) {
    return NULL;
  }
  flush_to_nvm(root_obj, sizeof(*root_obj));
  wmb();

  return root_obj;
}

ts_nvm_root_obj_t *nvm_load_numa_heap(const char *path, size_t sz,
                                      int *is_created) {
  ts_nvm_root_obj_t *root_obj;

  /* Get a root pointer */
  *is_created = 1;
  root_obj = nv_calloc(1, sizeof(*root_obj));
  if (unlikely(!root_obj)) {
    return NULL;
  }
  flush_to_nvm(root_obj, sizeof(*root_obj));
  wmb();

  return root_obj;
}

void nvm_heap_destroy(void) { /* Do nothing! */
}

void *nvm_alloc(size_t size) { return nv_malloc(size); }

void *nvm_alloc_numa(size_t size) {
  printf("!!!!!!!!!!!!!!!!!!!! NVM_NUMA_ALLOC !!!!!!!!!!!!!\n");
  return nv_malloc(size);
}

void *nvm_aligned_alloc(size_t alignment, size_t size) {
  return nv_aligned_alloc(alignment, size);
}

void nvm_free(void *ptr) { nv_free(ptr); }

#endif /* TS_NVM_IS_NV_JEMALLOC */
