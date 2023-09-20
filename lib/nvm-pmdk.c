#ifdef TS_NVM_IS_PMDK
#include "debug.h"
#include "nvm.h"
#include "port.h"
#include "util.h"
#include <libpmemobj.h>

static PMEMobjpool *__g_pop, *__g_pop_numa;
static PMEMobjpool *__g_master_pool, *__g_master_pool_numa;

#define LOCAL_SOCKET 0
#define NUMA_SOCKET 1
#define POOL_PATH "/mnt/pmem/ts-nvm0"
#define POOL_PATH_NUMA "/mnt/pmem1/ts-nvm1"
#define POOL_SIZE 100ul * 1024ul * 1024ul * 1024ul
#define POOL_PATH_MASTER "/mnt/pmem/ts-m0"
#define POOL_PATH_MASTER_NUMA "/mnt/pmem1/ts-m1"
#define POOL_SIZE_MASTER 2 * 1024ul * 1024ul * 1024ul /* 1GB*/

ts_nvm_root_obj_t *load_master_obj_numa_pool(const char *path, size_t sz) {
  PMEMoid root;
  ts_nvm_root_obj_t *root_obj;

  /* You should not init twice. */
  ts_assert(__g_master_pool_numa == NULL);

  /* Open a nvm heap */
  if (access(POOL_PATH_MASTER_NUMA, F_OK) != 0) {
    __g_master_pool_numa =
        pmemobj_create(POOL_PATH_MASTER_NUMA, POBJ_LAYOUT_NAME(master - numa),
                       POOL_SIZE_MASTER, 0666);
    if (unlikely(!__g_master_pool_numa)) {
      ts_trace(TS_ERROR, "failed to create master obj numa pool\n");
      return NULL;
    }
  } else {
    if ((__g_master_pool_numa = pmemobj_open(
             POOL_PATH_MASTER_NUMA, POBJ_LAYOUT_NAME(master - numa))) == NULL) {
      ts_trace(TS_ERROR, "failed to open the existing master numa pool\n");
      return NULL;
    }
  }

  /* Allocate a root in the nvmem pool, here on root_obj
   * will be the entry point to nv pool for all log allocations*/
  root = pmemobj_root(__g_master_pool_numa, sizeof(ts_nvm_root_obj_t));
  root_obj = pmemobj_direct(root);

  if (!root_obj)
    return NULL;
  return root_obj;
}

ts_nvm_root_obj_t *load_master_obj_pool(const char *path, size_t sz) {
  PMEMoid root;
  ts_nvm_root_obj_t *root_obj;

  /* You should not init twice. */
  ts_assert(__g_master_pool == NULL);

  /* Open a nvm heap */
  if (access(POOL_PATH_MASTER, F_OK) != 0) {
    __g_master_pool =
        pmemobj_create(POOL_PATH_MASTER, POBJ_LAYOUT_NAME(master - local),
                       POOL_SIZE_MASTER, 0666);
    if (unlikely(!__g_master_pool)) {
      ts_trace(TS_ERROR, "failed to create master obj local pool\n");
      return NULL;
    }
  } else {
    if ((__g_master_pool = pmemobj_open(
             POOL_PATH_MASTER, POBJ_LAYOUT_NAME(master - local))) == NULL) {
      ts_trace(TS_ERROR, "failed to open the existing master local pool\n");
      return NULL;
    }
  }

  /* Allocate a root in the nvmem pool, here on root_obj
   * will be the entry point to nv pool for all log allocations*/
  root = pmemobj_root(__g_master_pool, sizeof(ts_nvm_root_obj_t));
  root_obj = pmemobj_direct(root);

  if (!root_obj)
    return NULL;
  return root_obj;
}

ts_nvm_root_obj_t *nvm_load_heap(const char *path, size_t sz, int *is_created) {
  PMEMoid root;
  ts_nvm_root_obj_t *root_obj;

  /* You should not init twice. */
  ts_assert(__g_pop == NULL);

  /* Open a nvm heap */
  if (access(POOL_PATH, F_OK) != 0) {
    __g_pop =
        pmemobj_create(POOL_PATH, POBJ_LAYOUT_NAME(nvlog), POOL_SIZE, 0666);
    if (unlikely(!__g_pop)) {
      ts_trace(TS_ERROR, "failed to create pool\n");
      return NULL;
    }
    *is_created = 1;
  } else {
    if ((__g_pop = pmemobj_open(POOL_PATH, POBJ_LAYOUT_NAME(nvlog))) == NULL) {
      ts_trace(TS_ERROR, "failed to open the existing pool\n");
      return NULL;
    }
    *is_created = 0;
  }

  /* Allocate a root in the nvmem pool, here on root_obj
   * will be the entry point to nv pool for all log allocations*/
  root = pmemobj_root(__g_pop, sizeof(ts_nvm_root_obj_t));
  root_obj = pmemobj_direct(root);

  if (!root_obj)
    return NULL;

  if (*is_created)
    memset(root_obj, 0, sizeof(*root_obj));

  load_master_obj_pool(path, sz);
  return root_obj;
}

ts_nvm_root_obj_t *nvm_load_numa_heap(const char *path, size_t sz,
                                      int *is_created) {
  PMEMoid root;
  ts_nvm_root_obj_t *root_obj;

  /* You should not init twice. */
  ts_assert(__g_pop_numa == NULL);

  /* Open a NUMA nvm heap */
  if (access(POOL_PATH_NUMA, F_OK) != 0) {
    __g_pop_numa = pmemobj_create(POOL_PATH_NUMA, POBJ_LAYOUT_NAME(replica),
                                  POOL_SIZE, 0666);
    if (unlikely(!__g_pop_numa)) {
      ts_trace(TS_ERROR, "failed to create NUMA pool\n");
      return NULL;
    }
    *is_created = 1;
  } else {
    if ((__g_pop_numa =
             pmemobj_open(POOL_PATH_NUMA, POBJ_LAYOUT_NAME(replica))) == NULL) {
      ts_trace(TS_ERROR, "failed to open the existing NUMA pool\n");
      return NULL;
    }
    *is_created = 0;
  }

  /* Allocate a root in the nvmem pool, here on root_obj
   * will be the entry point to nv pool for all log allocations*/
  root = pmemobj_root(__g_pop_numa, sizeof(ts_nvm_root_obj_t));
  root_obj = pmemobj_direct(root);

  if (!root_obj)
    return NULL;

  if (*is_created)
    memset(root_obj, 0, sizeof(*root_obj));

  load_master_obj_numa_pool(path, sz);
  return root_obj;
}

void nvm_heap_destroy(void) {
  PMEMoid root;
  ts_nvm_root_obj_t *root_obj;

  /* set the root_obj->next to null to signify safe termination*/
  root = pmemobj_root(__g_pop, sizeof(ts_nvm_root_obj_t));
  root_obj = pmemobj_direct(root);
  root_obj->next = NULL;
  flush_to_nvm(root_obj, sizeof(*root_obj));
  smp_wmb();
  pmemobj_close(__g_pop);
  __g_pop = NULL;

  /* destroy the NUMA heap*/
  root = pmemobj_root(__g_pop_numa, sizeof(ts_nvm_root_obj_t));
  root_obj = pmemobj_direct(root);
  root_obj->next = NULL;
  flush_to_nvm(root_obj, sizeof(*root_obj));
  smp_wmb();
  pmemobj_close(__g_pop_numa);
  __g_pop_numa = NULL;

  /* close the master obj pools*/
  pmemobj_close(__g_master_pool);
  __g_master_pool = NULL;
  pmemobj_close(__g_master_pool_numa);
  __g_master_pool_numa = NULL;
}

/*nvm_alloc_numa is used internally to allocate
 * replicas in the NUMA domain*/
void *nvm_alloc_numa(size_t size) {
  int ret, chip, core;
  PMEMoid obj;
  PMEMobjpool *pop;

  read_coreid_rdtscp(&chip, &core);
  if (chip == LOCAL_SOCKET)
    pop = __g_pop_numa;
  else if (chip == NUMA_SOCKET)
    pop = __g_pop;
  else {
    printf("Wrong socket info at nvm alloc \n");
    exit(0);
  }
  ret = pmemobj_alloc(pop, &obj, size, 0, NULL, NULL);
  if (ret) {
    ts_trace(TS_ERROR, "log replica allocation failed\n");
    return NULL;
  }
  return pmemobj_direct(obj);
}

void *nvm_alloc(size_t size) {
  int ret, chip, core;
  PMEMoid buff;
  PMEMobjpool *pop;

  read_coreid_rdtscp(&chip, &core);
  if (chip == LOCAL_SOCKET)
    pop = __g_pop;
  else if (chip == NUMA_SOCKET)
    pop = __g_pop_numa;
  else {
    perror("Wrong socket info at nvm alloc \n");
    exit(0);
  }
  ret = pmemobj_alloc(pop, &buff, size, 0, NULL, NULL);
  if (ret) {
    ts_trace(TS_ERROR, "Log buffer allocation failed\n");
    return NULL;
  }
  return pmemobj_direct(buff);
}

void *nvm_alloc_master_obj(size_t alignment, size_t size) {
  int ret, chip, core;
  PMEMoid master_obj;
  PMEMobjpool *pop;

  read_coreid_rdtscp(&chip, &core);
  if (chip == LOCAL_SOCKET)
    pop = __g_master_pool;
  else if (chip == NUMA_SOCKET)
    pop = __g_master_pool_numa;
  else {
    perror("Wrong socket info at nvm alloc \n");
    exit(0);
  }
  /* TODO: need to implement aligned alloc */
  ret = pmemobj_alloc(pop, &master_obj, size, 0, NULL, NULL);
  if (ret) {
    ts_trace(TS_ERROR, "master_obj allocation failed\n");
    return NULL;
  }
  return pmemobj_direct(master_obj);
}

void *nvm_aligned_alloc(size_t alignment, size_t size) {
  /* TODO: need to implement aligned alloc */
  return nvm_alloc(size);
}

void nvm_free(void *ptr) {
  PMEMoid _ptr;

  _ptr = pmemobj_oid(ptr);
  pmemobj_free(&_ptr);
}

uint64_t get_pool_offset(void *ptr) {
  PMEMoid _ptr;
  _ptr = pmemobj_oid(ptr);
  return _ptr.off;
}

int get_pool_id(const void *ptr) {
  PMEMobjpool *pop;

  pop = pmemobj_pool_by_ptr(ptr);
  if (pop == __g_master_pool)
    return LOCAL_SOCKET;
  else if (pop == __g_master_pool_numa)
    return NUMA_SOCKET;
  else {
    perror("Wrong socket info at nvm alloc \n");
    exit(0);
  }
}

#endif /* TS_NVM_IS_PMDK */
