#ifndef _UTIL_H
#define _UTIL_H

#include "crc32.h"
#include "debug.h"
#include "port.h"
#include "timestone_i.h"
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MASK 0xFFFF

static inline int validate_ptr_checksum(ts_act_nvhdr_t *p_act_nvhdr);
/*
 * Alignment functions
 */
static inline void *align_ptr_to_cacheline(void *p) {
  return (void *)(((unsigned long)p + ~TS_CACHE_LINE_MASK) &
                  TS_CACHE_LINE_MASK);
}

static inline unsigned int align_uint_to_cacheline(unsigned int unum) {
  return (unum + ~TS_CACHE_LINE_MASK) & TS_CACHE_LINE_MASK;
}

static inline int is_ptr_cacheline_aligned(void *p) {
  return ((unsigned long)p & ~TS_CACHE_LINE_MASK) == 0;
}

static inline size_t align_size_t_to_pmem_page(size_t sz) {
  return (sz + ~TS_PMEM_PAGE_MASK) & TS_PMEM_PAGE_MASK;
}

/*
 * Locking functions
 */
static inline int try_lock(volatile unsigned int *lock) {
  if (*lock == 0 && smp_cas(lock, 0, 1))
    return 1;
  return 0;
}

static inline void unlock(volatile unsigned int *lock) { *lock = 0; }

/*
 * Object access functions
 */

static inline ts_obj_hdr_t *obj_to_obj_hdr(void *obj) {
  ts_obj_hdr_t *ohdr = (ts_obj_hdr_t *)obj;
  return &ohdr[-1];
}

static inline ts_obj_hdr_t *vobj_to_obj_hdr(volatile void *vobj) {
  return obj_to_obj_hdr((void *)vobj);
}

static inline void ts_assert_obj_type(void *obj, int type) {
  ts_obj_hdr_t *ohdr = obj_to_obj_hdr(obj);
  if (ohdr->type != type) {
    ts_trace(TS_INFO, "obj= %p\n", ohdr->obj);
    ts_trace(TS_INFO, "size= %d\n", ohdr->obj_size);
    ts_trace(TS_INFO, "type= %04x\n", ohdr->type);
  }
  ts_assert(obj_to_obj_hdr(obj)->type == type);
}

static inline ts_act_hdr_struct_t *obj_to_ahs(void *obj) {
  ts_act_hdr_struct_t *ahs;

  ahs = (ts_act_hdr_struct_t *)obj;
  ts_assert_obj_type(obj, TYPE_ACTUAL);
  return &ahs[-1];
}

static inline ts_act_hdr_struct_t *obj_to_vahs(void *obj) {
  ts_act_hdr_struct_t *ahs;

  ahs = (ts_act_hdr_struct_t *)obj;
  ts_assert_obj_type(obj, TYPE_NEW);
  return &ahs[-1];
}

static inline ts_act_hdr_struct_t *vobj_to_ahs(volatile void *vobj) {
  return obj_to_ahs((void *)vobj);
}

static inline ts_act_hdr_struct_t *vobj_to_vahs(volatile void *vobj) {
  return obj_to_vahs((void *)vobj);
}

static inline ts_cpy_hdr_struct_t *_obj_to_chs_unsafe(void *obj) {
  ts_cpy_hdr_struct_t *chs;

  chs = (ts_cpy_hdr_struct_t *)obj;
  return &chs[-1];
}

static inline ts_cpy_hdr_struct_t *obj_to_chs(void *obj, int type) {
  ts_cpy_hdr_struct_t *chs = _obj_to_chs_unsafe(obj);
#ifdef TS_ENABLE_ASSERT
  ts_assert_obj_type(obj, type);
#endif
  return chs;
}

static inline ts_cpy_hdr_struct_t *vobj_to_chs(volatile void *vobj, int type) {
  return obj_to_chs((void *)vobj, type);
}

static inline ts_ckpt_entry_t *obj_to_ckpt_ent(void *obj) {
  ts_ckpt_entry_t *ckpt_ent;

  ckpt_ent = (ts_ckpt_entry_t *)obj;
  ts_assert_obj_type(obj, TYPE_NVLOG_ENTRY);
  return &ckpt_ent[-1];
}

static inline ts_ckpt_entry_t *vobj_to_ckpt_ent(volatile void *vobj) {
  return obj_to_ckpt_ent((void *)vobj);
}

static inline ts_wrt_set_t *chs_obj_to_ws(void *obj) {
  ts_cpy_hdr_struct_t *chs = _obj_to_chs_unsafe(obj);
  ts_assert(obj_to_obj_hdr(obj)->type == TYPE_COPY ||
            obj_to_obj_hdr(obj)->type == TYPE_FREE ||
            obj_to_obj_hdr(obj)->type == TYPE_WRT_SET);
  return (ts_wrt_set_t *)chs->cpy_hdr.p_ws;
}

static inline ts_wrt_set_t *vchs_obj_to_ws(volatile void *obj) {
  return chs_obj_to_ws((void *)obj);
}

static inline int is_obj_actual(ts_obj_hdr_t *obj_hdr) {
#ifdef ts_disable_addr_actual_type_checking
  /* Test object type based on its type information
   * in the header. It may cause one cache miss. */
  int ret = ((obj_hdr->type == TYPE_ACTUAL) || (obj_hdr->type == TYPE_NEW));
  return ret;
#else
  /* Test if an object is in the log region or not.
   * If not, it is an actual object. We avoid one
   * memory reference so we may avoid one cache miss. */
  int ret = !port_addr_in_tvlog_region(obj_hdr);
  return ret;
#endif /* TS_DISABLE_ADDR_ACTUAL_TYPE_CHECKING */
}

static inline int is_obj_new(ts_obj_hdr_t *obj_hdr) {
  if (obj_hdr->type == TYPE_NEW)
    return 1;
  return 0;
}

static inline ts_act_nvhdr_t *get_act_nvhdr(volatile void *obj) {
  ts_obj_hdr_t *obj_hdr = vobj_to_obj_hdr(obj);

  if (unlikely(!is_obj_actual(obj_hdr))) {
    ts_assert(obj_hdr->type == TYPE_COPY);
    /* If this is the copy, get the actual object.
     * We should start in np_org_act, which is the
     * only way to access act_nvhdr_t */
    obj = vobj_to_chs(obj, TYPE_COPY)->cpy_hdr.p_act_vhdr->np_org_act;
  }

  ts_assert(obj_hdr->type != TYPE_NVLOG_ENTRY);
  if (vobj_to_obj_hdr(obj)->type == TYPE_NEW)
    return &vobj_to_vahs(obj)->act_nvhdr;

  ts_assert(vobj_to_obj_hdr(obj)->type == TYPE_ACTUAL);
  return &vobj_to_ahs(obj)->act_nvhdr;
}

static inline ts_act_vhdr_t *get_act_vhdr(void *obj) {
  ts_obj_hdr_t *obj_hdr = obj_to_obj_hdr(obj);
  ts_act_vhdr_t *p_act_vhdr;
  ts_act_nvhdr_t *p_act_nvhdr;
  ts_ckpt_entry_t *ckpt_entry;

  switch (obj_hdr->type) {
  case TYPE_ACTUAL:
    p_act_nvhdr = &obj_to_ahs(obj)->act_nvhdr;
#if 0 /* TODO: temporarily disable */
		if (p_act_nvhdr->gen_id != get_gen_id())
			return NULL;
#endif
    /* TODO: validate p_act_vhdr*/
    if (!validate_ptr_checksum(p_act_nvhdr)) {
      perror("media error detected on ptr");
      ts_trace(TS_INFO, "p_act_nvhdr= %p\n", p_act_nvhdr);
      ts_trace(TS_INFO, "p_act_vhdr= %p\n", p_act_nvhdr->p_act_vhdr);
      ts_trace(TS_INFO, "gen_id= %ld\n", p_act_nvhdr->gen_id);
      ts_assert(false);
      /*FIXME return EMEDIA*/
      exit(0);
    }
    p_act_vhdr = (ts_act_vhdr_t *)p_act_nvhdr->p_act_vhdr;
    break;
  case TYPE_NVLOG_ENTRY:
    ckpt_entry = obj_to_ckpt_ent(obj);
    ts_assert(ckpt_entry);
    p_act_nvhdr = &vobj_to_ahs(ckpt_entry->ckptlog_hdr.np_org_act)->act_nvhdr;
    /* TODO: validate p_act_vhdr*/
    if (!validate_ptr_checksum(p_act_nvhdr)) {
      perror("media error detected on ptr");
      ts_assert(false);
      // FIXME return EMEDIA
      exit(0);
    }
    p_act_vhdr = (ts_act_vhdr_t *)p_act_nvhdr->p_act_vhdr;
    break;
  case TYPE_COPY:
    p_act_vhdr =
        (ts_act_vhdr_t *)obj_to_chs(obj, TYPE_COPY)->cpy_hdr.p_act_vhdr;
    break;
  default:
    ts_assert(0 && "Never be here");
    p_act_vhdr = NULL;
    break;
  }

  return p_act_vhdr;
}

static inline ts_act_vhdr_t *get_vact_vhdr(volatile void *obj) {
  return get_act_vhdr((void *)obj);
}

static inline void *
get_org_act_obj_from_act_nvhdr(volatile ts_act_nvhdr_t *p_act_nvhdr) {
  ts_act_hdr_struct_t *ahs;

  ahs = (ts_act_hdr_struct_t *)p_act_nvhdr;
  return ahs->obj_hdr.obj;
}

static inline void *get_cur_act_obj(void *obj) {
  ts_act_vhdr_t *p_act_vhdr = get_act_vhdr(obj);
  if (unlikely(p_act_vhdr))
    return (void *)p_act_vhdr->np_cur_act;
  return obj;
}

static inline void *get_org_act_obj(void *obj) {
  ts_act_vhdr_t *p_act_vhdr = get_act_vhdr(obj);
  if (unlikely(p_act_vhdr))
    return (void *)p_act_vhdr->np_org_act;
  return obj;
}

static inline ts_act_hdr_struct_t *
get_org_ahs(volatile ts_act_vhdr_t *p_act_vhdr) {
  return vobj_to_ahs(p_act_vhdr->np_org_act);
}

static inline unsigned int get_entry_size(const ts_cpy_hdr_struct_t *chs) {
  return chs->obj_hdr.obj_size + chs->obj_hdr.padding_size;
}

static inline unsigned int sizeof_chs(const ts_cpy_hdr_struct_t *chs) {
  return sizeof(*chs) + get_entry_size(chs);
}

static inline void assert_chs_type(const ts_cpy_hdr_struct_t *chs) {
  ts_assert(chs->obj_hdr.type == TYPE_WRT_SET ||
            chs->obj_hdr.type == TYPE_COPY || chs->obj_hdr.type == TYPE_FREE ||
            chs->obj_hdr.type == TYPE_BOGUS);
}

static inline ts_act_vhdr_t *alloc_act_vhdr(void *np_org_act) {
  ts_act_vhdr_t *p_act_vhdr;

  ts_assert(np_org_act);

  /* p_act_vhdr should be aligned to
   * a cacheline size to reduce false sharing. */
  p_act_vhdr = (ts_act_vhdr_t *)port_aligned_alloc(TS_CACHE_LINE_SIZE,
                                                   sizeof(*p_act_vhdr));
  if (unlikely(p_act_vhdr == NULL))
    return NULL;

  p_act_vhdr->p_copy = NULL;
  p_act_vhdr->p_lock = NULL;
  p_act_vhdr->np_org_act = np_org_act;
  p_act_vhdr->np_cur_act = np_org_act;
  /* init and ptr_tag*/
  p_act_vhdr->ptr_tag = obj_to_obj_hdr(np_org_act)->ptr_tag;
  p_act_vhdr->tombstone_clk = MAX_VERSION;
  smp_wmb();
  return p_act_vhdr;
}

static inline void free_act_vhdr(ts_act_vhdr_t *p_act_vhdr) {
  /* TODO: kernel port? jemalloc? */
  return free(p_act_vhdr);
}

/*
 * Pointer set
 */

static inline int ptrset_init(ts_ptr_set_t *ptrset) {
  ts_assert(ptrset->ptrs == NULL);

  ptrset->num_ptrs = 0;
  ptrset->num_max_ptrs = TS_INIT_PTR_SET_SIZE;
  ptrset->ptrs = (void **)port_alloc(ptrset->num_max_ptrs * sizeof(void *));
  if (unlikely(ptrset->ptrs == 0)) {
    return ENOMEM;
  }

  return 0;
}

static inline int assign_ptrset_init(ts_assign_ptr_set_t *ptrset) {
  ptrset->num_ptrs = 0;
  ptrset->num_max_ptrs = TS_INIT_PTR_SET_SIZE;
  ptrset->array = (ts_assign_ptr_entry_t *)port_alloc(
      ptrset->num_max_ptrs * sizeof(ts_assign_ptr_entry_t));
  if (unlikely(ptrset->array == 0)) {
    return ENOMEM;
  }
  return 0;
}

static inline void ptrset_deinit(ts_ptr_set_t *ptrset) {
  if (ptrset->ptrs) {
    port_free(ptrset->ptrs);
    ptrset->ptrs = NULL;
  }
}

static inline void assign_ptrset_deinit(ts_assign_ptr_set_t *ptrset) {
  if (ptrset->array) {
    port_free(ptrset->array);
    ptrset->array = NULL;
  }
}

static inline int ptrset_expand(ts_ptr_set_t *ptrset) {
  unsigned int new_num;
  void **ptrs;

  new_num = ptrset->num_max_ptrs + TS_INIT_PTR_SET_SIZE;
  ptrs = (void **)port_realloc(ptrset->ptrs, new_num * sizeof(void *));
  if (unlikely(ptrs == NULL)) {
    return ENOMEM;
  }

  ts_trace(TS_FP, "[%s:%d] expand free ptr array: %d(%p)-> %d(%p)\n", __func__,
           __LINE__, ptrset->num_max_ptrs, ptrset->ptrs, new_num, ptrs);

  ptrset->num_max_ptrs = new_num;
  ptrset->ptrs = ptrs;
  return 0;
}

static inline int assign_ptrset_expand(ts_assign_ptr_set_t *ptrset) {
  unsigned int new_num;
  ts_assign_ptr_entry_t *array;

  new_num = ptrset->num_max_ptrs + TS_INIT_PTR_SET_SIZE;
  array = (ts_assign_ptr_entry_t *)port_realloc(ptrset->array,
                                                new_num * sizeof(*array));
  if (unlikely(array == NULL)) {
    return ENOMEM;
  }

  ts_trace(TS_FP, "[%s:%d] expand assign ptr array: %d(%p)-> %d(%p)\n",
           __func__, __LINE__, ptrset->num_max_ptrs, ptrset->array, new_num,
           array);
  ptrset->num_max_ptrs = new_num;
  ptrset->array = array;
  return 0;
}

static inline int ptrset_is_member(ts_ptr_set_t *ptrset, void *p_act) {
  unsigned int i;

  for (i = 0; i < ptrset->num_ptrs; ++i) {
    if (ptrset->ptrs[i] == p_act)
      return 1;
  }
  return 0;
}

static inline int ptrset_get_index(ts_ptr_set_t *ptrset, void *p_act) {
  unsigned int i;

  for (i = 0; i < ptrset->num_ptrs; ++i) {
    if (ptrset->ptrs[i] == p_act) {
      // ts_trace(TS_INFO, "obj %p (%p) found at %d \n", p_act, ptrset->ptrs[i],
      // i);
      return i;
    }
  }
  return -1;
}

static inline void ptrset_reset(ts_ptr_set_t *ptrset) { ptrset->num_ptrs = 0; }

static inline void assign_ptrset_reset(ts_assign_ptr_set_t *ptrset) {
  ptrset->num_ptrs = 0;
}

static inline int ptrset_push(ts_ptr_set_t *ptrset, void *p) {
  if (unlikely(ptrset->num_ptrs >= ptrset->num_max_ptrs)) {
    int ret = ptrset_expand(ptrset);
    if (ret) {
      ts_assert(0 && "Fail to expand a ptr_set");
      return ret;
    }
  }

  ptrset->ptrs[ptrset->num_ptrs++] = p;
  return 0;
}

static inline void *ptrset_get(ts_ptr_set_t *ptrset, unsigned int pos) {
  ts_assert(ptrset->ptrs != NULL);

  if (unlikely(pos > ptrset->num_ptrs))
    return NULL;
  return ptrset->ptrs[pos];
}

static inline int ptrset_put(ts_ptr_set_t *ptrset, unsigned int pos, void *p) {
  ts_assert(ptrset->ptrs != NULL);

  if (unlikely(pos > ptrset->num_ptrs))
    return -1;
  ptrset->ptrs[pos] = p;
  return 0;
}

static inline unsigned int ptrset_get_num_ptrs(ts_ptr_set_t *ptrset) {
  return ptrset->num_ptrs;
}

static inline unsigned int
ptrset_get_assign_num_ptrs(ts_assign_ptr_set_t *ptrset) {
  return ptrset->num_ptrs;
}

static inline int _ptrset_push(ts_ptr_set_t *ptrset, void *p) {
  int pos;

  if (unlikely(ptrset->num_ptrs >= ptrset->num_max_ptrs)) {
    int ret = ptrset_expand(ptrset);
    if (ret) {
      ts_assert(0 && "Fail to expand a ptr_set");
      return -1;
    }
  }
  pos = ptrset->num_ptrs;
  ptrset->ptrs[pos] = p;
  ++ptrset->num_ptrs;
  return pos;
}

static inline int assign_ptrset_push(ts_assign_ptr_set_t *ptrset, void **p,
                                     int index) {
  int ret, pos;
  ts_assign_ptr_entry_t *entry;

  if (unlikely(ptrset->num_ptrs >= ptrset->num_max_ptrs)) {
    ret = assign_ptrset_expand(ptrset);
    if (ret) {
      ts_assert(0 && "Fail to expand a ptr_set");
      return ret;
    }
  }
  pos = ptrset->num_ptrs;
  entry = &ptrset->array[pos];
  entry->p_obj = p;
  entry->alloc_index = index;
  ++ptrset->num_ptrs;
  return 0;
}

static inline void *ptrset_pop(ts_ptr_set_t *ptrset) {
  if (ptrset->num_ptrs > 0) {
    ts_trace(TS_FP, "ptrset_pop: num_ptrs= %d, ptr= %p\n", ptrset->num_ptrs,
             ptrset->ptrs[ptrset->num_ptrs]);
    return ptrset->ptrs[ptrset->num_ptrs--];
  }
  return NULL;
}

static inline ts_assign_ptr_entry_t *
assign_ptrset_get(ts_assign_ptr_set_t *ptrset, unsigned int pos) {
  ts_assert(ptrset->array != NULL);
  if (unlikely(pos > ptrset->num_ptrs))
    return NULL;
  return &ptrset->array[pos];
}

/*
 * list manipulation
 */
static inline void init_ts_list(ts_list_t *list) {
  list->next = list;
  list->prev = list;
}

static inline void ts_list_add(ts_list_t *_new, ts_list_t *head) {
  head->next->prev = _new;
  _new->next = head->next;
  _new->prev = head;
  head->next = _new;
}

static inline void ts_list_del(ts_list_t *entry) {
  entry->next->prev = entry->prev;
  entry->prev->next = entry->next;
}

static inline int ts_list_empty(const ts_list_t *head) {
  return head->next == head && head->prev == head;
}

static inline void ts_list_rotate_left(ts_list_t *head) {
  /* Rotate a list in counterclockwise direction:
   *
   * Before rotation:
   *  [T3]->{{H}}->[T0]->[T1]->[T2]
   *  /|\                       |
   *   +------------------------+
   *
   * After rotation:
   *  [T3]->[T0]->{{H}}->[T1]->[T2]
   *  /|\                       |
   *   +------------------------+
   */
  if (!ts_list_empty(head)) {
    ts_list_t *first;
    first = head->next;
    ts_list_del(first);
    ts_list_add(first, head->prev);
  }
}

/*
 * Misc. functions
 */

static inline const char *req2str(unsigned char req) {
  switch (req) {
  case RECLAIM_TVLOG_BEST_EFFORT:
    return "RECLAIM_TVLOG_BEST_EFFORT";
  case RECLAIM_TVLOG_CKPT:
    return "RECLAIM_TVLOG_CKPT";
  case RECLAIM_CKPTLOG_BEST_EFFORT:
    return "RECLAIM_CKPTLOG_BEST_EFFORT";
  case RECLAIM_CKPTLOG_WRITEBACK:
    return "RECLAIM_CKPTLOG_WRITEBACK";
  case RECLAIM_CKPTLOG_WRITEBACK_ALL:
    return "RECLAIM_CKPTLOG_WRITEBACK_ALL";
  }
  return "";
}

/*
 * random number for canary
 * canary access functions
 * TODO: refactor utility fuctions without variables*/
static inline uint64_t get_canary_64() {
  uint64_t rand;
  int ret;

  ret = rdrand_64(&rand);
  if (unlikely(!ret)) {
    perror("canary generation failed \n");
    ts_assert(false);
  }
  return rand;
}

static inline uint32_t get_canary_32() {
  uint32_t rand;
  int ret;

  ret = rdrand_32(&rand);
  if (unlikely(!ret)) {
    perror("canary generation failed \n");
    ts_assert(false);
  }
  return rand;
}

static inline uint16_t get_canary_16() {
  uint16_t rand;
  int ret;

  ret = rdrand_16(&rand);
  if (unlikely(!ret)) {
    perror("canary generation failed \n");
    ts_assert(false);
  }
  return rand;
}

static inline uint64_t get_tag_mask() {
  uint64_t mask = MASK;

  return mask <<= 48;
}

static inline uint64_t get_addr_mask() {
  uint64_t mask = MASK;

  mask <<= 48;
  return ~mask;
}

static inline uint64_t generate_tag() {
  uint64_t tag;
  int ret;

  ret = rdrand_64(&tag);
  if (unlikely(!ret)) {
    perror("canary generation failed \n");
    ts_assert(false);
  }
  tag %= UINT16_MAX;
  tag <<= 48;
  return tag;
}

static inline void *encode_tag_to_ptr(void *obj, uint64_t tag) {
  uint64_t addr = (uint64_t)obj;

  addr |= tag;
  return (void *)addr;
}

static inline void *encode_ptr(void *obj, uint64_t tag) {
  return encode_tag_to_ptr(obj, tag);
}

static inline uint64_t extract_tag(void *obj) {
  uint64_t mask, tag;
  uint64_t addr = (uint64_t)obj;

  mask = get_tag_mask();
  tag = addr & mask;
  return tag;
}

static inline void *restore_ptr(void *obj) {
  uint64_t mask;
  uint64_t addr = (uint64_t)obj;

  mask = get_addr_mask();
  addr &= mask;
  return (void *)addr;
}

static inline void *obj_canary_from_ahs(ts_act_hdr_struct_t *ahs) {
  return (ahs->obj_hdr.obj + ahs->obj_hdr.obj_size);
}

static inline void *obj_canary_from_chs(ts_cpy_hdr_struct_t *chs) {
  return (chs->obj_hdr.obj + chs->obj_hdr.obj_size);
}

/* utility functions for checksum
 * calculation and validation
 *
 * */
static inline void *get_ahs_offset(ts_act_hdr_struct_t *ahs) {
  return (void *)&ahs->act_nvhdr.index;
}

static inline void *get_ckpt_offset(void *data) {
  return ((char *)data + CHECKSUM_SIZE);
}

static inline size_t get_checksum_size(void *obj, unsigned char type) {
  size_t size;

  switch (type) {
  case TYPE_ACTUAL:
    /*	size = sizeof(obj_to_ahs(obj)->act_nvhdr.index) +
            sizeof(ts_obj_hdr_t) + obj_to_obj_hdr(obj)->obj_size;	*/
    size = sizeof(int) + sizeof(ts_obj_hdr_t) + obj_to_obj_hdr(obj)->obj_size;
    break;
  case TYPE_NVLOG_ENTRY:
    size =
        sizeof(ts_ckpt_entry_t) - CHECKSUM_SIZE + obj_to_obj_hdr(obj)->obj_size;
    break;
  default:
    /* never be here*/
    ts_assert(0 && "Never be here");
    size = 0;
    break;
  }
  return size;
}

static inline uint32_t generate_obj_checksum(void *obj, unsigned char type) {
#ifdef ENABLE_CHECKSUM
  void *data;
  size_t size;

  switch (type) {
  case TYPE_ACTUAL:
    data = get_ahs_offset(obj_to_ahs(obj));
    size = get_checksum_size(obj, type);
    break;
  case TYPE_NVLOG_ENTRY:
    data = get_ckpt_offset(obj_to_ckpt_ent(obj));
    size = get_checksum_size(obj, type);
    break;
  default:
    /* never be here*/
    ts_assert(0 && "Never be here");
    data = NULL;
    size = 0;
    break;
  }
  return crc32(data, size);
#else
  return 0;
#endif
}

static inline uint32_t generate_ptr_checksum(ts_act_nvhdr_t *p_act_nvhdr) {
#ifdef ENABLE_CHECKSUM
  void *data;
  size_t size;

  data = &p_act_nvhdr->p_act_vhdr;
  size = sizeof(void *) + sizeof(unsigned long);
  return crc32(data, size);
#else
  return 0;
#endif
}

static inline int validate_ptr_checksum(ts_act_nvhdr_t *p_act_nvhdr) {
#ifdef ENABLE_CHECKSUM
  uint32_t ptr_checksum, checksum;

  ptr_checksum = p_act_nvhdr->vptr_checksum;
  if (unlikely(ptr_checksum == INVALID_CHECKSUM))
    return 1;
  checksum = generate_ptr_checksum(p_act_nvhdr);
  if (unlikely(ptr_checksum != checksum)) {
    ts_trace(TS_INFO, "ptr_checksum= %" PRIu32 "\n", ptr_checksum);
    ts_trace(TS_INFO, "cal_checksum= %" PRIu32 "\n", checksum);
    return 0;
  }
  return 1;
#else
  return 1;
#endif
}

static inline int validate_obj_checksum(void *obj, unsigned char type) {
#ifdef ENABLE_CHECKSUM
  uint32_t obj_checksum, checksum;

  ts_assert(type == TYPE_ACTUAL || type == TYPE_NVLOG_ENTRY);
  if (likely(type != TYPE_ACTUAL))
    obj_checksum = obj_to_ckpt_ent(obj)->nvlog_hdr.checksum;
  else {
    obj_checksum = obj_to_ahs(obj)->act_nvhdr.checksum;
  }
  if (unlikely(obj_checksum == INVALID_CHECKSUM))
    return 1;
  checksum = generate_obj_checksum(obj, type);
  if (obj_checksum != checksum) {
    ts_trace(TS_INFO, "obj_checksum= %" PRIu32 "\n", obj_checksum);
    ts_trace(TS_INFO, "cal_checksum= %" PRIu32 "\n", checksum);
    ts_trace(TS_INFO, "type= %04x\n", type);
    // ts_assert(obj_checksum == checksum);
    return 0;
  }
  // printf("checksum validation done %04x\n", type);
  return 1;
#else
  return 1;
#endif
}

/* utility functions for replica writes and read
 * will be used by qp and recovery threads
 * to perform stripped disk writes (qp)
 * and to recover from hw error*/
static inline int get_fd_index(int socket_id, int file_id) {
  int file_index;

  file_index = (socket_id * _N_DISK_FILES) + file_id;

  return file_index;
}

static inline int get_disk_file_id(uint64_t nvm_offset) {
  int chunk_id = 0, column_id = 0;

  chunk_id = nvm_offset / (CHUNK_SIZE);
  column_id = chunk_id % _N_DISK_FILES;
  return column_id;
}

static inline uint64_t get_disk_offset(uint64_t nvm_offset) {
  int chunk_id, row_id;
  uint64_t chunk_offset, disk_offset;

  chunk_id = nvm_offset / (CHUNK_SIZE);
  row_id = chunk_id / _N_DISK_FILES;
  chunk_offset = nvm_offset % CHUNK_SIZE;
  disk_offset = (row_id * CHUNK_SIZE) + chunk_offset;

  return disk_offset;
}

#ifdef __cplusplus
}
#endif
#endif
