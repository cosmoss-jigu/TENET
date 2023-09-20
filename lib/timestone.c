#ifndef __KERNEL__
#include "timestone.h"
#else
#include <linux/timestone.h>
#endif

#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>
#include "timestone_i.h"
#include "port.h"
#include "util.h"
#include "debug.h"
#include "tvlog.h"
#include "oplog.h"
#include "ckptlog.h"
#include "nvm.h"
#include "clock.h"
#include "qp.h"
#include "isolation.h"
#include "recovery.h"
#include "disk.h"

static unsigned long __g_gen_id;
static ts_recovery_t __g_recovery;

/*
 * Utility functions
 */

static inline unsigned long get_gen_id(void)
{
	return __g_gen_id;
}

/*
 * External APIs
 */
int __init ts_init(ts_conf_t *conf)
{
	static int init = 0;
	ts_nvm_root_obj_t *nvm_root_obj, *nvm_root_obj_numa;
	int need_recovery, rc;

	/* Compile time sanity check */
	//	static_assert(TS_AHS_SIZE == sizeof(ts_act_hdr_struct_t));
	static_assert(sizeof(ts_act_hdr_struct_t) < 2 * L1_CACHE_BYTES);
	static_assert(sizeof(ts_cpy_hdr_struct_t) <= 2 * L1_CACHE_BYTES);
	static_assert((TS_TVLOG_SIZE & (TS_TVLOG_SIZE - 1)) == 0);

	/* Make sure whether it is initialized once */
	if (!smp_cas(&init, 0, 1))
		return -EBUSY;

	/* Init */
	init_clock();

	nvm_root_obj =
		nvm_init_heap(conf->nvheap_path,
			      align_size_t_to_pmem_page(conf->nvheap_size),
			      &need_recovery);
	if (unlikely(!nvm_root_obj)) {
		ts_trace(TS_ERROR, "Fail to initialize an nvm heap\n");
		return ENOMEM;
	}

	nvm_root_obj_numa =
		nvm_init_numa_heap(conf->nvheap_path,
				   align_size_t_to_pmem_page(conf->nvheap_size),
				   &need_recovery);
	if (unlikely(!nvm_root_obj_numa)) {
		ts_trace(TS_ERROR, "Fail to initialize NUMA nvm heap\n");
		return ENOMEM;
	}

	rc = nvlog_init(nvm_root_obj);
	if (rc) {
		ts_trace(TS_ERROR, "Fail to initialize a nvlog region\n");
		return rc;
	}

	__g_gen_id = nvm_get_gen_id();
	rc = port_tvlog_region_init(TS_TVLOG_SIZE, TS_MAX_THREAD_NUM);
	if (rc) {
		ts_trace(TS_ERROR, "Fail to initialize a log region\n");
		return rc;
	}
	rc = init_qp(conf->n_threads);
	if (rc) {
		ts_trace(TS_ERROR, "Fail to initialize a qp thread\n");
		return rc;
	}
	/* init IO_URING */

	/* Setup recovery information */
	__g_recovery.root = nvm_root_obj;
	__g_recovery.op_exec = conf->op_exec;

	/* If necessary, perform recovery */
	if (unlikely(need_recovery)) {
		rc = perform_recovery(&__g_recovery);
		if (unlikely(rc)) {
			ts_trace(TS_ERROR, "Fail to recover logs\n");
			return rc;
		}
	}

	return 0;
}
early_initcall(ts_init);

void __ts_finish(void)
{
	deinit_qp();
	port_tvlog_region_destroy();
}

void __ts_unload_nvm(void)
{
	nvm_heap_destroy();
}

void ts_finish(void)
{
	__ts_finish();
	__ts_unload_nvm();
}

ts_thread_struct_t *ts_thread_alloc(void)
{
	return port_alloc(sizeof(ts_thread_struct_t));
}
EXPORT_SYMBOL(ts_thread_alloc);

#ifdef TS_ENABLE_MOBJ_REPLICATION
static int is_replication_done(ts_thread_struct_t *thread)
{
	if (thread->rs_head == thread->rs_tail)
		/* replication is done*/
		return 1;
	return 0;
}
#endif

void ts_drain_replica_set(ts_thread_struct_t *thread)
{
#ifdef TS_ENABLE_MOBJ_REPLICATION
	int count = 0;
	bool *wait_for_drain;

	while (thread->rs_head != thread->rs_tail) {
		port_cpu_relax_and_yield();
		smp_mb();
		count++;
		if (count == 10000) {
			//	printf("Waiting for replication to finish... \n");
			count = 0;
		}
		//		printf("rs_head= %d\n rs_tail= %d\n", thread->rs_head, thread->rs_tail);
	}
	wait_for_drain = get_drain_ptr();
	smp_atomic_store(wait_for_drain, true);
	while (smp_atomic_load(wait_for_drain)) {
		//		printf("Waiting for IO_URING buffers to drain... \n");
		port_cpu_relax_and_yield();
		smp_mb();
		count++;
		if (count == 10000) {
			//	printf("Waiting for IO_URING buffers to drain... \n");
			count = 0;
		}
	}
	thread->rs_head = thread->rs_tail = -1;
#endif
	return;
}

void ts_thread_free(ts_thread_struct_t *self)
{
	smp_atomic_store(&self->live_status, THREAD_DEAD_ZOMBIE);

	/* If the log is not completely reclaimed yet,
	 * defer the free until it is completely reclaimed.
	 * In this case, we just move the thread to the zombie
	 * list and the qp thread will eventually reclaim
	 * the log. */
	smp_mb();
#ifdef TS_ENABLE_MOBJ_REPLICATION
	if (tvlog_used(&self->tvlog) == 0 &&
	    ckptlog_used(&self->ckptlog) == 0 && is_replication_done(self)) {
		stat_thread_merge(self);
		tvtlog_destroy(&self->tvlog);
		ckptlog_destroy(&self->ckptlog, &self->ckptlog_replica);
		oplog_destroy(&self->oplog, &self->oplog_replica);
		ptrset_deinit(&self->tx_alloc_set);
		ptrset_deinit(&self->tx_free_set);
		ptrset_deinit(&self->ckpt_free_set);
		assign_ptrset_deinit(&self->tx_assign_set);
		port_free(self);
	}
#else
	if (tvlog_used(&self->tvlog) == 0 &&
	    ckptlog_used(&self->ckptlog) == 0) {
		stat_thread_merge(self);
		tvtlog_destroy(&self->tvlog);
		ckptlog_destroy(&self->ckptlog, &self->ckptlog_replica);
		oplog_destroy(&self->oplog, &self->oplog_replica);
		ptrset_deinit(&self->tx_alloc_set);
		ptrset_deinit(&self->tx_free_set);
		ptrset_deinit(&self->ckpt_free_set);
		assign_ptrset_deinit(&self->tx_assign_set);
		port_free(self);
	}

#endif
}
EXPORT_SYMBOL(ts_thread_free);

void ts_thread_init_x(ts_thread_struct_t *self, unsigned short flags)
{
	int rc, chip, core;

	/* Zero out self */
	memset(self, 0, sizeof(*self));

	/* Initialize clocks*/
	self->clks.__last_ckpt = MIN_VERSION;
	self->clks.__min_ckpt_reclaimed = MAX_VERSION;
	read_coreid_rdtscp(&chip, &core);
	self->socket_id = chip;
	ts_trace(TS_DEBUG, "socket_id: %d \n", self->socket_id);

	/* Initialize free pointer arrays */
	rc = ptrset_init(&self->tx_alloc_set);
	if (unlikely(rc))
		goto err_out;

	rc = ptrset_init(&self->tx_nv_alloc_set);
	if (unlikely(rc))
		goto err_out;

	rc = ptrset_init(&self->tx_free_set);
	if (unlikely(rc))
		goto err_out;

	rc = ptrset_init(&self->ckpt_free_set);
	if (unlikely(rc))
		goto err_out;

	rc = assign_ptrset_init(&self->tx_assign_set);
	if (unlikely(rc))
		goto err_out;

	/* Initialize isolation info */
	rc = isolation_init(&self->isolation);
	if (self->tid == 1) {
		printf("########## ISOLATION LEVEL:%d ########### \n",
		       self->isolation.level);
	}
	if (unlikely(rc))
		goto err_out;

	/* Allocate cacheline-aligned log space on DRAM */
	rc = tvlog_create(self, &self->tvlog);
	if (unlikely(rc))
		goto err_out;

	/* Set the status status if it is in a recovery mode */
	self->in_recovery_mode = (flags == STATUS_NVLOG_RECOVERY);

	/* Allocate cacheline-aligned oplog space on NVM */
	oplog_create(self, &self->oplog, TS_OPLOG_SIZE, flags, false);
	ts_assert(self->oplog.buffer ==
		  align_ptr_to_cacheline((void *)self->oplog.buffer));

#ifdef TS_ENABLE_OPLOG_REPLICATION
	/*Allocate oplog replica*/
	oplog_create(self, &self->oplog_replica, TS_OPLOG_SIZE, flags, true);
	ts_assert(self->oplog_replica.buffer ==
		  align_ptr_to_cacheline((void *)self->oplog_replica.buffer));
	ts_trace(TS_DEBUG, "oplog_replica: %p\n", &self->oplog_replica);
#endif

	/* Allocate cacheline-aligned ckptlog space on NVM */
	ckptlog_create(self, &self->ckptlog, TS_CKPTLOG_SIZE, flags, false);
	ts_assert(self->ckptlog.buffer ==
		  align_ptr_to_cacheline((void *)self->ckptlog.buffer));

#ifdef TS_ENABLE_CKPTLOG_REPLICATION
	/* allocate ckptlog replica*/
	ckptlog_create(self, &self->ckptlog_replica, TS_CKPTLOG_SIZE, flags,
		       true);
	ts_assert(self->ckptlog_replica.buffer ==
		  align_ptr_to_cacheline((void *)self->ckptlog_replica.buffer));
	ts_trace(TS_DEBUG, "ckptlog_replica: %p\n", &self->oplog_replica);
#endif

#ifdef TS_ENABLE_MOBJ_REPLICATION
	self->rs_head = self->rs_tail = -1;
#endif

	/* Add this to the global list */
	register_thread(self);
	smp_mb();
	return;
err_out:
	/* TODO: change the return type to int to return an errno. */
	ts_assert(0);
	return;
}
EXPORT_SYMBOL(ts_thread_init_x);

void ts_thread_init(ts_thread_struct_t *self)
{
	ts_thread_init_x(self, STATUS_NVLOG_NORMAL);
}
EXPORT_SYMBOL(ts_thread_init);

static inline void try_reclaim_logs(ts_thread_struct_t *self)
{
	if (unlikely(self->reclaim.requested)) {
		if (self->reclaim.tvlog)
			tvlog_reclaim(&self->tvlog, &self->ckptlog,
				      &self->ckptlog_replica);
		if (self->reclaim.ckptlog)
			ckptlog_reclaim(&self->ckptlog, &self->ckptlog_replica);
	}
}

void ts_thread_finish(ts_thread_struct_t *self)
{
	/* Reclaim logs as much as it can. */
	try_reclaim_logs(self);
	oplog_reclaim(&self->oplog, RECLAIM_OPLOG_NORMAL);

#ifdef TS_ENABLE_OPLOG_REPLICATION
	/* reclaim the replica as well*/
	oplog_reclaim(&self->oplog_replica, RECLAIM_OPLOG_NORMAL);
#endif

	/* Deregister this thread from the live list */
	self->qp_info.need_wait = 0;
	deregister_thread(self);

	/* If logs are not completely reclaimed, add it to
	 * the zombie list to reclaim the tvlog or ckptlog later. */
#ifdef TS_ENABLE_MOBJ_REPLICATION
	if (tvlog_used(&self->tvlog) || ckptlog_used(&self->ckptlog) ||
	    !is_replication_done(self)) {
		smp_atomic_store(&self->live_status, THREAD_LIVE_ZOMBIE);
		zombinize_thread(self);
	} else {
		isolation_deinit(&self->isolation);
		tvtlog_destroy(&self->tvlog);
		ckptlog_destroy(&self->ckptlog, &self->ckptlog_replica);
		oplog_destroy(&self->oplog, &self->oplog_replica);
		stat_thread_merge(self);
	}
#else
	if (tvlog_used(&self->tvlog) || ckptlog_used(&self->ckptlog)) {
		smp_atomic_store(&self->live_status, THREAD_LIVE_ZOMBIE);
		zombinize_thread(self);
	} else {
		isolation_deinit(&self->isolation);
		tvtlog_destroy(&self->tvlog);
		ckptlog_destroy(&self->ckptlog, &self->ckptlog_replica);
		oplog_destroy(&self->oplog, &self->oplog_replica);
		stat_thread_merge(self);
	}

#endif
}
EXPORT_SYMBOL(ts_thread_finish);

void ts_stat_alloc_act_obj(ts_thread_struct_t *self, size_t size)
{
	ts_act_hdr_struct_t *ahs;

	stat_thread_acc(self, n_alloc_act_obj_bytes, sizeof(*ahs) + size);
}
EXPORT_SYMBOL(ts_stat_alloc_act_obj);

void ts_update_index(void *obj, int index)
{
	ts_act_nvhdr_t *p_act_nvhdr;

	obj = restore_ptr(obj);

	/* temproraily disable until array apis are fixed*/
	//ts_assert(obj_to_obj_hdr(obj)->type == TYPE_NEW);
	p_act_nvhdr = get_act_nvhdr(obj);
	p_act_nvhdr->index = index;
	flush_to_nvm(p_act_nvhdr, sizeof(*p_act_nvhdr));
	smp_wmb();

	/* temproraily disable until array apis are fixed*/
	//ts_assert(obj_to_obj_hdr(obj)->type == TYPE_NEW);
	return;
}
EXPORT_SYMBOL(ts_update_index);

int ts_get_index(void *obj)
{
	ts_act_nvhdr_t *p_act_nvhdr;

	p_act_nvhdr = get_act_nvhdr(obj);
	return p_act_nvhdr->index;
}
EXPORT_SYMBOL(ts_get_index);

volatile char *ts_get_base_addr(volatile void *obj)
{
	ts_obj_hdr_t *obj_hdr;
	ts_act_hdr_struct_t *ahs;
	ts_act_nvhdr_t *p_act_nvhdr;
	int curr_index, size;
	void *base_obj;

	obj_hdr = vobj_to_obj_hdr(obj);
	if (!is_obj_actual(obj_hdr)) {
		ts_assert(obj_hdr->type == TYPE_COPY);
		obj = vobj_to_chs(obj, TYPE_COPY)
			      ->cpy_hdr.p_act_vhdr->np_org_act;
	}
	ahs = vobj_to_ahs(obj);
	curr_index = ahs->act_nvhdr.index;
	if (unlikely(!curr_index))
		return obj;
	size = ahs->obj_hdr.obj_size;
	base_obj = (((char *)obj) - ((sizeof(*ahs) + size) * curr_index));
	p_act_nvhdr = get_act_nvhdr((void *)base_obj);
	curr_index = p_act_nvhdr->index;
	ts_assert(curr_index == 0);
	return (char *)base_obj;
}

volatile void *ts_get_offset(void *obj, int index)
{
	ts_obj_hdr_t *obj_hdr;
	ts_act_nvhdr_t *p_act_nvhdr;
	int size;
	volatile char *base_obj;
	volatile void *offset;

	base_obj = ts_get_base_addr(obj);
	obj_hdr = vobj_to_obj_hdr(base_obj);
	size = obj_hdr->obj_size;
	offset = base_obj + ((sizeof(ts_act_hdr_struct_t) + size) * index);
	p_act_nvhdr = get_act_nvhdr(offset);
	if (!p_act_nvhdr) {
		ts_trace(TS_ERROR, "NVhdr does not exists, Invalid object\n");
		EFAULT;
	}
	ts_assert(p_act_nvhdr->index == index);
	return offset;
}
EXPORT_SYMBOL(ts_get_offset);

void tss_insert_canary_act(ts_act_hdr_struct_t *ahs)
{
	uint64_t *p_obj_canary = (uint64_t *)obj_canary_from_ahs(ahs);
	uint64_t ohdr_canary_mask = (uint64_t)&ahs->obj_hdr.canary;
	uint64_t obj_canary_mask = (uint64_t)p_obj_canary;

	ts_trace(TS_DEBUG, "=========================================\n");
	ts_trace(TS_DEBUG, "ahs= %p\n", ahs);
	ahs->act_nvhdr.canary = get_canary_64();
	ahs->obj_hdr.canary = ahs->act_nvhdr.canary ^ ohdr_canary_mask;
	*p_obj_canary = ahs->obj_hdr.canary ^ obj_canary_mask;
	ts_trace(TS_DEBUG, "C0= %ld \t C1= %ld \t C2= %ld\n",
		 ahs->act_nvhdr.canary, ahs->obj_hdr.canary, *p_obj_canary);
	ts_trace(TS_DEBUG, "=========================================\n");
}

void *ts_alloc(size_t size)
{
	ts_act_hdr_struct_t *ahs;

	ahs = port_alloc(sizeof(*ahs) + size + CANARY_SIZE);
	if (unlikely(ahs == NULL))
		return NULL;
	memset(ahs, 0, sizeof(*ahs));
	ahs->obj_hdr.type = TYPE_NEW;
	ahs->obj_hdr.obj_size = size;
	ahs->obj_hdr.ptr_tag = generate_tag();
	ahs->act_nvhdr.gen_id = INVALID_GEN_ID;
	ahs->act_nvhdr.checksum = INVALID_CHECKSUM;
	ahs->act_nvhdr.vptr_checksum = INVALID_CHECKSUM;
	tss_insert_canary_act(ahs);
	return ahs->obj_hdr.obj;
}
EXPORT_SYMBOL(ts_alloc);

void *ts_alloc_unsafe(size_t size, bool flush)
{
	ts_act_hdr_struct_t *ahs;

	/* Alloc and init
	 * NOTE: It should be aligned by 16 bytes for smp_cas16b() */
	ahs = nvm_aligned_alloc(16, sizeof(*ahs) + size + CANARY_SIZE);
	if (unlikely(ahs == NULL))
		return NULL;

	memset(ahs, 0, sizeof(*ahs));
	ahs->obj_hdr.type = TYPE_ACTUAL;
	ahs->obj_hdr.obj_size = size;
	/* FIXME: adhoc fix for rlu bench and b+tree*/
	ahs->obj_hdr.ptr_tag = 0;
	ahs->act_nvhdr.gen_id = INVALID_GEN_ID;
	ahs->act_nvhdr.checksum = INVALID_CHECKSUM;
	ahs->act_nvhdr.vptr_checksum = INVALID_CHECKSUM;
	if (flush) {
		/* wmb() at commit time in ts_update_index*/
		flush_to_nvm(ahs, sizeof(ahs));
	}
	tss_insert_canary_act(ahs);
	return ahs->obj_hdr.obj;
}
EXPORT_SYMBOL(ts_alloc_unsafe);

void tss_copy_canary_act(ts_act_hdr_struct_t *ahs, ts_act_hdr_struct_t *vahs)
{
	uint64_t *p_vobj_canary = (uint64_t *)obj_canary_from_ahs(vahs);
	uint64_t *p_nvobj_canary = (uint64_t *)obj_canary_from_ahs(ahs);

	ahs->obj_hdr.canary = vahs->obj_hdr.canary;
	ahs->act_nvhdr.canary = vahs->act_nvhdr.canary;
	*p_nvobj_canary = *p_vobj_canary;
}

void *ts_alloc_internal(size_t size, ts_act_hdr_struct_t *vahs)
{
	ts_act_hdr_struct_t *ahs;

	/* Alloc and init
	 * NOTE: It should be aligned by 16 bytes for smp_cas16b() */
	ahs = nvm_alloc_master_obj(16, sizeof(*ahs) + size + CANARY_SIZE);
	if (unlikely(ahs == NULL))
		return NULL;

	memset(ahs, 0, sizeof(*ahs));
	ahs->obj_hdr.type = TYPE_ACTUAL;
	ahs->obj_hdr.obj_size = size;
	ahs->obj_hdr.ptr_tag = vahs->obj_hdr.ptr_tag;
	ahs->act_nvhdr.gen_id = vahs->act_nvhdr.gen_id;
	ahs->act_nvhdr.index = vahs->act_nvhdr.index;
	ahs->act_nvhdr.checksum = vahs->act_nvhdr.checksum;
	ahs->act_nvhdr.vptr_checksum = vahs->act_nvhdr.vptr_checksum;
	tss_copy_canary_act(ahs, vahs);
	return ahs->obj_hdr.obj;
}

void ts_free(ts_thread_struct_t *self, void *obj)
{
	/* NOTE: free from non-volatile memory */
	ts_act_hdr_struct_t *ahs;
	void *p_act;

	if (unlikely(obj == NULL))
		return;

	if (unlikely(self == NULL)) {
		ahs = obj_to_ahs(obj);
		nvm_free(ahs);
		return;
	}
	ts_assert(self->run_cnt & 0x1);

	p_act = get_org_act_obj(obj);
	ts_assert(get_act_vhdr(obj) == obj_to_ahs(p_act)->act_nvhdr.p_act_vhdr);
	ts_assert(obj_to_ahs(p_act)->obj_hdr.type == TYPE_ACTUAL);
	ts_assert(obj_to_ahs(p_act)->act_nvhdr.p_act_vhdr->p_lock != NULL);

	ptrset_push(&self->tx_free_set, p_act);
}
EXPORT_SYMBOL(ts_free);

void ts_begin(ts_thread_struct_t *self, int isolation_level)
{
	/* Reclaim log if requested at the transaction boundary. */
	try_reclaim_logs(self);

	/* Secure enough tvlog space below high watermark */
	tvlog_reclaim_below_high_watermark(&self->tvlog, &self->ckptlog,
					   &self->ckptlog_replica);

	/* Object data writes should not be reordered with metadata writes. */
	smp_wmb_tso();

	/* Get it started */
	isolation_reset(&self->isolation, isolation_level);
	smp_faa(&(self->run_cnt), 1);
	self->local_clk = get_clock_relaxed();

	/* Get the latest view */
	smp_rmb();

	stat_thread_inc(self, n_starts);
	ts_assert(self->tvlog.cur_wrt_set == NULL);
	ts_assert(self->tx_free_set.num_ptrs == 0);
}
EXPORT_SYMBOL(ts_begin);

static void flush_new_act(ts_thread_struct_t *self)
{
	ts_ptr_set_t *tx_alloc_set;
	ts_act_hdr_struct_t *ahs;
	size_t size;

	/* Call clwb for all newly allocated actual
	 * objects. Note we don't need to call wmb()
	 * here because they should be flushed before
	 * next checkpointing. */
	tx_alloc_set = &self->tx_alloc_set;
	while ((ahs = ptrset_pop(tx_alloc_set))) {
		size = sizeof(*ahs) + ahs->obj_hdr.obj_size;
		flush_to_nvm(ahs, size);
		stat_thread_acc(self, n_flush_new_act_bytes, size);
	}
}

static void _flush_new_act(ts_thread_struct_t *self)
{
	ts_ptr_set_t *tx_nv_alloc_set;
	ts_act_hdr_struct_t *ahs;
	size_t size;
	unsigned int i;
	void *obj;

	/* Call clwb for all newly allocated actual
	 * objects. Note we don't need to call wmb()
	 * here because they should be flushed before
	 * next checkpointing. */
	tx_nv_alloc_set = &self->tx_nv_alloc_set;
	for (i = 0; i < tx_nv_alloc_set->num_ptrs; ++i) {
		obj = tx_nv_alloc_set->ptrs[i];
		ahs = obj_to_ahs(obj);
		ts_assert(ahs->obj_hdr.type == TYPE_ACTUAL);
		size = sizeof(*ahs) + ahs->obj_hdr.obj_size;
		flush_to_nvm(ahs, size);
		stat_thread_acc(self, n_flush_new_act_bytes, size);
	}
	ptrset_reset(tx_nv_alloc_set);
}

static int validate_master_obj(ts_act_hdr_struct_t *ahs)
{
	uint64_t *p_obj_canary = (uint64_t *)obj_canary_from_ahs(ahs);
	uint64_t c0 = ahs->act_nvhdr.canary;
	uint64_t c1 = ahs->obj_hdr.canary;
	uint64_t c2 = *p_obj_canary;
	uint64_t c1_mask = (uint64_t)&ahs->obj_hdr.canary;
	uint64_t c2_mask = (uint64_t)p_obj_canary;

	if (c1 == (c0 ^ c1_mask) && c2 == (c1 ^ c2_mask)) {
		ts_trace(TS_DEBUG, "=======================================\n");
		ts_trace(TS_DEBUG, "### master object validated ### \n");
		ts_trace(TS_DEBUG, "C0= %ld, C1= %ld, C2= %ld \n", c0, c1, c2);
		ts_trace(TS_DEBUG, "=======================================\n");
		return 1;
	}
	//ts_assert(0 && "spatial safety violation for master object");
	return 0;
}

static int allocate_nv_orig_obj(ts_thread_struct_t *self)
{
	ts_ptr_set_t *tx_alloc_set, *tx_nv_alloc_set;
	ts_assign_ptr_set_t *tx_assign_set;
	ts_obj_hdr_t *obj_hdr;
	ts_act_hdr_struct_t *ahs;
	int num_alloc_ptrs, num_assign_ptrs;
	int i;
	void *vobj, *nvobj;
	size_t size;

	tx_alloc_set = &self->tx_alloc_set;
	tx_nv_alloc_set = &self->tx_nv_alloc_set;
	tx_assign_set = &self->tx_assign_set;
	num_alloc_ptrs = ptrset_get_num_ptrs(tx_alloc_set);
	num_assign_ptrs = ptrset_get_assign_num_ptrs(tx_assign_set);
	if (num_alloc_ptrs == 0 || num_assign_ptrs == 0)
		return -1;
	ts_trace(TS_DEBUG, "num_alloc_ptrs= %d \n", num_alloc_ptrs);
	for (i = 0; i < num_alloc_ptrs; ++i) {
		/* pop a ptr from tx_alloc_set*/
		vobj = ptrset_get(tx_alloc_set, i);
		/* get ohdr to retrieve size for alloc*/
		obj_hdr = obj_to_obj_hdr(vobj);
		ts_assert(obj_hdr->type == TYPE_NEW);
		size = obj_hdr->obj_size;
		ahs = obj_to_vahs(vobj);
		/* validate the volatile ahs for spatial safety*/
		if (!validate_master_obj(ahs)) {
			ts_trace(
				TS_INFO,
				"Spatial Safety Violation Detected in Tx Commit (master obj)\n");
			return 0;
		}
		/* allocate master on nvm*/
		nvobj = ts_alloc_internal(size, ahs);
		ts_trace(TS_DEBUG, "nv_obj= %p\n", nvobj);
		/* add nvobj in tx_nv_alloc_set*/
		_ptrset_push(tx_nv_alloc_set, nvobj);
		ts_trace(TS_DEBUG, "v_obj= %p \t size= %ld\n", vobj, size);
		ts_trace(TS_DEBUG, "n_obj= %p \t size= %ld\n", nvobj, size);
		//ts_assert(ret == i);
	}
	return 1;
}

static void assign_nv_orig_obj(ts_thread_struct_t *self)
{
	ts_ptr_set_t *tx_nv_alloc_set;
	ts_assign_ptr_set_t *tx_assign_set;
	ts_assign_ptr_entry_t *entry;
	int num_alloc_ptrs, num_assign_ptrs;
	int i;
	void *nvobj, *enc_nvobj;

	tx_nv_alloc_set = &self->tx_nv_alloc_set;
	tx_assign_set = &self->tx_assign_set;
	num_alloc_ptrs = ptrset_get_num_ptrs(tx_nv_alloc_set);
	num_assign_ptrs = ptrset_get_assign_num_ptrs(tx_assign_set);
	if (num_alloc_ptrs == 0 || num_assign_ptrs == 0)
		return;
	for (i = 0; i < num_assign_ptrs; ++i) {
		/* get an entry from tx_assign_set*/
		entry = assign_ptrset_get(tx_assign_set, i);
		ts_assert(entry != NULL);
		/* retrieve the corresponding nvobj in tx_alloc_set*/
		nvobj = ptrset_get(tx_nv_alloc_set, entry->alloc_index);
		ts_assert(obj_to_obj_hdr(nvobj)->type == TYPE_ACTUAL);
		/* update the ptr to point to nvobj
		 * encode the obj before assignment*/
		enc_nvobj = encode_ptr(nvobj, obj_to_obj_hdr(nvobj)->ptr_tag);
		*(entry->p_obj) = enc_nvobj;
	}
	assign_ptrset_reset(tx_assign_set);
	return;
}

static void update_nv_orig_obj(ts_thread_struct_t *self)
{
	ts_obj_hdr_t *obj_hdr;
	ts_ptr_set_t *tx_alloc_set, *tx_nv_alloc_set;
	int num_v_ptrs, i;
	void *vobj, *nvobj;
	size_t size;
#ifdef TS_ENABLE_MOBJ_REPLICATION
	int tail;
#endif

	tx_alloc_set = &self->tx_alloc_set;
	tx_nv_alloc_set = &self->tx_nv_alloc_set;
	ts_assert(ptrset_get_num_ptrs(tx_alloc_set) ==
		  ptrset_get_num_ptrs(tx_nv_alloc_set));
	num_v_ptrs = ptrset_get_num_ptrs(tx_alloc_set);
	if (!num_v_ptrs)
		return;
	for (i = 0; i < num_v_ptrs; ++i) {
		vobj = ptrset_get(tx_alloc_set, i);
		obj_hdr = obj_to_obj_hdr(vobj);
		ts_assert(obj_hdr->type == TYPE_NEW);
		size = obj_hdr->obj_size;
		nvobj = ptrset_get(tx_nv_alloc_set, i);
		memcpy(nvobj, vobj, size);
		port_free(obj_to_vahs(vobj));
		ts_assert(obj_to_ahs(nvobj)->act_nvhdr.checksum ==
			  INVALID_CHECKSUM);
		obj_to_ahs(nvobj)->act_nvhdr.checksum = generate_obj_checksum(
			nvobj, obj_to_obj_hdr(nvobj)->type);

#ifdef TS_ENABLE_MOBJ_REPLICATION
		/* prepare the nvobj for replication to the disk */
		tail = (self->rs_tail + 1) % MAX_SET_SIZE;
		/* TODO: fix for tail and head pointer
		 * when replica set is full backoff and retry*/
		if (tail == self->rs_head ||
		    (self->rs_head == -1 && tail == MAX_SET_SIZE - 1)) {
			perror("Replica set size exceeded \n");
			ts_trace(TS_INFO, "head= %d tail= %d\n", self->rs_head,
				 self->rs_tail);
			exit(0);
		}
		self->tx_replica_set[tail].src = obj_to_ahs(nvobj);
		self->tx_replica_set[tail].len =
			sizeof(ts_act_hdr_struct_t) + size + CANARY_SIZE;
		self->tx_replica_set[tail].offset =
			get_pool_offset(obj_to_ahs(nvobj));
		self->tx_replica_set[tail].commit_clk = self->local_clk;
		self->rs_tail = tail;
#endif
	}
	ptrset_reset(tx_alloc_set);
	return;
}

void replicate_mobj_to_disk(ts_thread_struct_t *self, ts_disk_entry_t *entries)
{
#if 0	
	int i;
	printf("!!!!!!!!!!!!!!! DISK WRITE WARN !!!!!!!!!!!!!!!!! \n");
	if (!n_objs)
		return;
	for (i = 0; i < n_objs; ++i) {
		pwrite(fds[entries[i].file_id], entries[i].src, entries[i].len, 
				entries[i].file_offset);
		stat_thread_acc(self, n_disk_write_bytes, entries[i].len);
	}
	return;
#endif
}

int ts_end(ts_thread_struct_t *self)
{
	int ret;

	ts_assert(self->run_cnt & 0x1);

	/* Do not commit in a recovery mode. */
	if (unlikely(self->in_recovery_mode)) {
		return 1;
	}

	/* Read set validation */
	if (!validate_read_set(&self->isolation)) {
		ts_abort(self);
		stat_thread_inc(self, n_aborts_validation);
		return 0;
	}

	/* Object data writes should not be reordered with metadata writes. */
	smp_wmb_tso();

	if (!allocate_nv_orig_obj(self)) {
		ts_trace(TS_INFO,
			 "Aborting the Transaction for graceful exit\n");
		return ESPATIAL;
	}
	assign_nv_orig_obj(self);
	update_nv_orig_obj(self);

	/* If it is a writer, commit its changes. */
	if (self->is_write_detected) {
		ret = tvlog_commit(&self->tvlog, &self->oplog,
				   &self->oplog_replica, &self->tx_free_set,
				   self->local_clk, &self->op_info);
		if (!ret) {
			ts_trace(
				TS_INFO,
				"Aborting the Transaction for graceful exit\n");
			return ESPATIAL;
		}
		self->is_write_detected = 0;
	}

	/* Now every thing is done. */
	self->run_cnt++;

	/* Flush all newly allocated objects */
	_flush_new_act(self);
	ts_assert(self->tx_alloc_set.num_ptrs == 0);
	ts_assert(self->tx_nv_alloc_set.num_ptrs == 0);
	ts_assert(self->tx_assign_set.num_ptrs == 0);

	/* Reclaim log if requested at the transaction boundary. */
	try_reclaim_logs(self);

	stat_thread_inc(self, n_finish);
	ts_assert(self->tvlog.cur_wrt_set == NULL);
	ts_assert(self->tx_free_set.num_ptrs == 0);

#ifdef TS_ENABLE_MOBJ_REPLICATION
	replicate_mobj_to_disk(self, self->tx_replica_set);
#endif

	/* Success */
	return 1;
}
EXPORT_SYMBOL(ts_end);

static void free_new_act(ts_thread_struct_t *self)
{
	ts_ptr_set_t *tx_alloc_set;
	ts_act_hdr_struct_t *ahs;

	/* Call clwb for all newly allocated actual
	 * objects. Note we don't need to call wmb()
	 * here because they should be flushed before
	 * next checkpointing. */
	tx_alloc_set = &self->tx_alloc_set;
	while ((ahs = ptrset_pop(tx_alloc_set))) {
		nvm_free(ahs);
	}
}

static void free_new_vact(ts_thread_struct_t *self)
{
	ts_ptr_set_t *tx_alloc_set;
	ts_act_hdr_struct_t *ahs;

	/* Call clwb for all newly allocated actual
	 * objects. Note we don't need to call wmb()
	 * here because they should be flushed before
	 * next checkpointing. */
	tx_alloc_set = &self->tx_alloc_set;
	while ((ahs = ptrset_pop(tx_alloc_set))) {
		port_free(ahs);
	}
	/* reset the assign_ptrset*/
	assign_ptrset_reset(&self->tx_assign_set);
}

void ts_abort(ts_thread_struct_t *self)
{
	/* Object data writes should not be reordered with metadata writes. */
	smp_wmb_tso();

	ts_assert(self->run_cnt & 0x1);
	self->run_cnt++;

	if (self->tvlog.cur_wrt_set) {
		tvlog_abort(&self->tvlog, &self->tx_free_set);
		self->is_write_detected = 0;
	}

	/* free all newly allocated objects */
	free_new_vact(self);
	if (self->tx_alloc_set.num_ptrs != 0 ||
	    self->tx_assign_set.num_ptrs != 0) {
		ts_trace(TS_INFO, "num_alloc_ptrs= %d \t num_assign_ptrs= %d",
			 self->tx_alloc_set.num_ptrs,
			 self->tx_assign_set.num_ptrs);
		ts_assert(self->tx_alloc_set.num_ptrs == 0);
		ts_assert(self->tx_assign_set.num_ptrs == 0);
	}

	/* Reclaim log if requested at the transaction boundary. */
	try_reclaim_logs(self);

	/* Help log reclamation upon abort */
	oplog_reclaim(&self->oplog, RECLAIM_OPLOG_NORMAL);

#ifdef TS_ENABLE_OPLOG_REPLICATION
	oplog_reclaim(&self->oplog_replica, RECLAIM_OPLOG_NORMAL);
#endif

	/* Prepare next ts_reader_lock() by performing memory barrier. */
	smp_mb();

	stat_thread_inc(self, n_aborts);
	ts_assert(self->tvlog.cur_wrt_set == NULL);
	ts_assert(self->tx_free_set.num_ptrs == 0);
}
EXPORT_SYMBOL(ts_abort);

void _dbg_assert_chs_copy(const char *f, const int l, ts_cpy_hdr_struct_t *chs)
{
#ifdef TS_ENABLE_ASSERT
	if (chs->obj_hdr.type != TYPE_COPY) {
		ts_dbg_dump_all_version_chain_chs(f, l, chs);
	}
#endif
	ts_assert(chs->obj_hdr.type == TYPE_COPY);
}

int validate_ptr(void *obj)
{
	uint64_t tag, ohdr_tag;

	tag = extract_tag(obj);
	ohdr_tag = obj_to_obj_hdr(restore_ptr(obj))->ptr_tag;
	if (unlikely(tag != ohdr_tag)) {
		perror("Temporal safety violation detected\n");
		ts_trace(TS_INFO, "tag= %ld \t obj_tag= %ld\n", tag, ohdr_tag);
		ts_assert(tag == ohdr_tag);
		return ETEMPORAL;
	}
	return 0;
}

int is_ptr_valid(ts_act_vhdr_t *p_act_vhdr, unsigned long local_clk)
{
	if (p_act_vhdr->ptr_tag == INVALID_PTR_TAG &&
	    p_act_vhdr->tombstone_clk != MAX_VERSION &&
	    gt_clock(local_clk, p_act_vhdr->tombstone_clk)) {
		ts_trace(TS_INFO, "p_act_vhdr->p_copy= %p\n",
			 p_act_vhdr->p_copy);
		ts_trace(TS_INFO, "local_clk= %ld\n", local_clk);
		ts_trace(TS_INFO, "_tomb_clk= %ld\n",
			 p_act_vhdr->tombstone_clk);
		return ETEMPORAL;
	}
	return 0;
}

void *ts_deref(ts_thread_struct_t *self, void *obj)
{
	volatile void *p_copy;
	void *p_latest;
	ts_cpy_hdr_struct_t *chs;
	ts_act_vhdr_t *p_act_vhdr;
	unsigned long wrt_clk, last_ckpt_clk, local_clk;
	void *enc_obj = obj;

	if (unlikely(!obj))
		return NULL;

	obj = restore_ptr(enc_obj);
	if (unlikely(is_obj_new(obj_to_obj_hdr(obj))))
		return obj;

	/* Case 0: if it is not an actual, that means
	 * obj is already dereferenced. */
	if (unlikely(!is_obj_actual(obj_to_obj_hdr(obj)))) {
		ts_trace(TS_DEBUG, "type= %04x\n", obj_to_obj_hdr(obj)->type);
		ts_trace(TS_DEBUG, "size= %04x\n",
			 obj_to_obj_hdr(obj)->obj_size);
		ts_trace(TS_DEBUG, "obj= %p\n", obj);
		ts_trace(TS_DEBUG, "obj= %s\n", (char *)obj);
		return obj;
	}

	/* validate the obj for temporal safety
	 * this check will catch if a free-ed master has been 
	 * reallocated with the same address*/
	if (validate_ptr(enc_obj) == ETEMPORAL) {
		/* FIXME: return error code*/
		exit(0);
	}

	/* Case 1: it does not have a volatile header,
	 * which means the object is the original actual
	 * and hasn't been updated so far. */
	ts_assert(obj_to_obj_hdr(obj)->type == TYPE_ACTUAL);
	p_act_vhdr = get_act_vhdr(obj);
	if (unlikely(!p_act_vhdr)) {
		/* TODO: cleanup checksum*/
		if (!validate_obj_checksum(obj, obj_to_obj_hdr(obj)->type)) {
			perror(" checksum validation failed for act obj");
			ts_assert(false);
			/*FIXME: return EMEDIA*/
			exit(0);
		}
		read_set_add(&self->isolation, p_act_vhdr, NULL, obj);
		ts_assert(obj);
		return obj;
	}
	if (p_act_vhdr) {
		/*this check will catch if copy is free-ed but still the 
		* live ptr exists i.e., before checkpointing tombstone and
		* physically free-ing the master*/
		if (is_ptr_valid(p_act_vhdr, self->local_clk) == ETEMPORAL) {
			perror("Temporal safety (user-after-free) violation detected (cpy_obj)\n");
			// FIXME: return ETEMP
			exit(0);
		}
	}

	/* Case 2: it has a volatile header. */
	p_copy = p_act_vhdr->p_copy;
	p_latest = (void *)p_copy;
	if (unlikely(p_copy)) {
		last_ckpt_clk = self->clks.__last_ckpt;
		local_clk = self->local_clk;

		do {
			chs = vobj_to_chs(p_copy, TYPE_COPY);
			wrt_clk = get_wrt_clk(chs, local_clk);
			_dbg_assert_chs_copy(__func__, __LINE__, chs);

			if (lt_clock(wrt_clk, local_clk)) { /* TIME: < */
				read_set_add(&self->isolation, p_act_vhdr,
					     p_latest, (void *)p_copy);
				return (void *)p_copy;
			}

			/* All copies in tvlog that are older than
			 * last checkpoint timestamp (last_ckpt) are
			 * guaranteed to be checkpointed meaning
			 * there are no longer exist in tvlog.
			 * Therefore we should stop version chain
			 * traversal here and fall back
			 * to the np_cur_master. */
			if (unlikely(lt_clock(chs->cpy_hdr.wrt_clk_next,
					      last_ckpt_clk))) /* TIME: < */
				break;
			p_copy = chs->cpy_hdr.p_copy;
		} while (p_copy);
	}

	/* Returns the current master object */
	obj = (void *)p_act_vhdr->np_cur_act;
	if (!validate_obj_checksum(obj, obj_to_obj_hdr(obj)->type)) {
		/* TODO: cleanup checksum*/
		perror(" checksum validation failed for ckpt obj \n");
		ts_assert(false);
		/*FIXME: return EMEDIA*/
		exit(0);
	}
	read_set_add(&self->isolation, p_act_vhdr, p_latest, obj);
	ts_assert(obj);
	return obj;
}
EXPORT_SYMBOL(ts_deref);

static inline int try_lock_obj(ts_act_vhdr_t *p_act_vhdr,
			       volatile void *p_old_copy,
			       volatile void *p_new_copy)
{
	int ret;

	if (p_act_vhdr->p_lock != NULL || p_act_vhdr->p_copy != p_old_copy)
		return 0;

	smp_wmb_tso();
	ret = smp_cas(&p_act_vhdr->p_lock, NULL, p_new_copy);
	if (!ret)
		return 0; /* smp_cas() failed */

	if (unlikely(p_act_vhdr->p_copy != p_old_copy)) {
		ts_assert(p_act_vhdr->p_lock == p_new_copy);

		/* If it is ABA, unlock and return false */
		smp_wmb();
		p_act_vhdr->p_lock = NULL;
		return 0;
	}

	/* Finally succeeded. Updating p_copy of p_new_copy
	 * will be done upon commit. */
	return 1;
}

static int try_alloc_act_vhdr(void *obj)
{
	ts_act_nvhdr_t *p_act_nvhdr;
	ts_act_nvhdr_t old_act_nvhdr, new_act_nvhdr;
	ts_act_vhdr_t *p_act_vhdr;

	p_act_nvhdr = get_act_nvhdr(obj);
	old_act_nvhdr = *p_act_nvhdr;

	/* If another thread already allocates,
	 * then yield to that thread. */
	if (old_act_nvhdr.p_act_vhdr != NULL) {
		return 0;
	}

	p_act_vhdr = alloc_act_vhdr(obj);
	new_act_nvhdr.p_act_vhdr = p_act_vhdr;
	new_act_nvhdr.gen_id = get_gen_id();

	if (unlikely(new_act_nvhdr.p_act_vhdr == NULL)) {
		ts_trace(TS_ERROR, "Fail to allocate p_act_vhdr\n");
		return 0;
	}

	/* update volatile header and a generation id
	 * CAS16 fails due to canary
	 * replaced the logic with 8byte CAS*/
	if (p_act_nvhdr->p_act_vhdr || !smp_cas(&p_act_nvhdr->p_act_vhdr, NULL,
						new_act_nvhdr.p_act_vhdr)) {
		// Another thread already allocates and updates.
		free_act_vhdr((void *)new_act_nvhdr.p_act_vhdr);
		return 0;
	}
	smp_atomic_store(&p_act_nvhdr->gen_id, new_act_nvhdr.gen_id);
	/*update ptr checksum after gen_id and vhdr update*/
	p_act_nvhdr->vptr_checksum = generate_ptr_checksum(p_act_nvhdr);
	ts_trace(TS_DEBUG, "vptr_checksum= %" PRIu32 "\n",
		 p_act_nvhdr->vptr_checksum);
	ts_trace(TS_DEBUG, "p_act_nvhdr= %p\n", p_act_nvhdr);
	ts_trace(TS_DEBUG, "p_act_vhdr= %p\n", p_act_nvhdr->p_act_vhdr);
	ts_trace(TS_DEBUG, "gen_id= %ld\n", p_act_nvhdr->gen_id);
	return 1;
}

int _ts_try_lock(ts_thread_struct_t *self, void **pp_obj, size_t size)
{
	volatile void *p_lock, *p_old_copy, *p_new_copy, *p_act;
	ts_cpy_hdr_struct_t *chs;
	ts_act_vhdr_t *p_act_vhdr;
	unsigned long local_clk;
	void *obj;
	int bogus_allocated;

	/* Check if stale read already occured */
	if (stale_read_occurred(&self->isolation)) {
		return 0;
	}

	obj = *pp_obj;
	if (obj_to_obj_hdr(obj)->type == TYPE_NEW)
		return 1;
	ts_warning(obj != NULL);
	ts_assert(obj_to_obj_hdr(obj)->type != TYPE_NEW);
	p_act_vhdr = get_act_vhdr(obj);

	/* If act_vhdr is not yet allocated, try to allocate it. */
	if (unlikely(!p_act_vhdr)) {
		if (!try_alloc_act_vhdr(obj)) {
			return 0;
		}
		p_act_vhdr = (ts_act_vhdr_t *)get_act_nvhdr(obj)->p_act_vhdr;
	}
	ts_assert(p_act_vhdr != NULL);
	ts_assert(p_act_vhdr ==
		  obj_to_ahs(get_org_act_obj(obj))->act_nvhdr.p_act_vhdr);

	/* If an object is already locked, it cannot lock again
	 * except when a lock is locked again by the same thread. */
	p_act = p_act_vhdr->np_cur_act;
	p_lock = p_act_vhdr->p_lock;
	if (unlikely(p_lock)) {
#ifdef TS_NESTED_LOCKING
		ts_wrt_set_t *ws;

		/* Free is never unlocked. */
		if (vobj_to_obj_hdr(p_lock)->type == TYPE_FREE) {
			return 0;
		}

		/* If the same thread tries to acquire the same lock,
		 * the previous transaction should be committed
		 * before starting the second transaction and it makes
		 * get_raw_wrt_clk(chs) non-MAX_VERSION. */
		ws = vchs_obj_to_ws(p_lock);
		ts_assert(ws);
		if (self != ws->thread ||
		    self->run_cnt != ws->thread->run_cnt) {
			return 0;
		}

		/* If the lock is acquired by the same thread,
		 * allow to lock again according to the original
		 * RLU semantics.
		 *
		 * WARNING: We do not promote immutable try_lock_const()
		 * to mutable try_lock_const().
		 */
		*pp_obj = (void *)p_lock;
		ts_assert(vobj_to_obj_hdr(p_lock)->type == TYPE_COPY);
		return 1;
#else
		return 0;
#endif /* TS_NESTED_LOCKING */
	}

	/* To maintain a linear version history, we should allow
	 * lock acquisition only when the local version of a thread
	 * is greater or equal to the writer version of an object.
	 * Otherwise it allows inconsistent, mixed, views
	 * of the local version and the writer version.
	 * That is because acquiring a lock fundamentally means
	 * advancing the version. */
	p_old_copy = p_act_vhdr->p_copy;
	if (p_old_copy) {
		chs = vobj_to_chs(p_old_copy, TYPE_COPY);
		/* It guarantees that clock gap between two versions of
		 * an object is greater than 2x ORDO_BOUNDARY. */
		local_clk = self->local_clk;
		if (gte_clock(get_wrt_clk(chs, local_clk),
			      local_clk)) /* TIME: >= */
			return 0;
	}
	/* this check will catch if copy is free-ed but still the 
	* live ptr exists i.e., before checkpointing tombstone and
	* physically free-ing the master
	if (is_ptr_valid(p_act_vhdr, self->local_clk) == ETEMPORAL) {
			perror("Temporal safety (user-after-free) violation detected (cpy_obj)\n");
			// FIXME: return ETEMP
			exit(0);
		}*/

	/* Secure log space and initialize a header */
	chs = tvlog_append_begin(&self->tvlog, p_act_vhdr, size,
				 &bogus_allocated);
	p_new_copy = (volatile void *)chs->obj_hdr.obj;

	/* Try lock */
	if (!try_lock_obj(p_act_vhdr, p_old_copy, p_new_copy)) {
		tvlog_append_abort(&self->tvlog, chs);
		return 0;
	}

	/* Duplicate the copy */
	if (!p_old_copy) {
		p_act = p_act_vhdr->np_cur_act;
		memcpy((void *)p_new_copy, (void *)p_act, size);
	} else
		memcpy((void *)p_new_copy, (void *)p_old_copy, size);
	tvlog_append_end(&self->tvlog, chs, bogus_allocated);

	/* Succeed in locking */
	if (self->is_write_detected == 0)
		self->is_write_detected = 1;
	*pp_obj = (void *)p_new_copy;

	/* Add this to the write set. */
	write_set_add(&self->isolation, (void *)p_new_copy);

	ts_assert(p_act_vhdr->p_lock);
	ts_assert(p_act_vhdr ==
		  obj_to_ahs(get_org_act_obj(obj))->act_nvhdr.p_act_vhdr);
	ts_assert(obj_to_ahs(get_org_act_obj(obj))
			  ->act_nvhdr.p_act_vhdr->p_lock != NULL);
	return 1;
}
EXPORT_SYMBOL(_ts_try_lock);

int _ts_try_lock_const(ts_thread_struct_t *self, void *obj, size_t size)
{
	/* Try_lock_const is nothing but a try lock with size zero
 	 * so we can omit copy from/to p_act.
	 *
	 * NOTE: obj is not updated after the call (not void ** but void *) */
	return _ts_try_lock(self, &obj, 0);
}
EXPORT_SYMBOL(_ts_try_lock_const);

int ts_cmp_ptrs(void *obj1, void *obj2)
{
	if (likely(obj1 != NULL))
		obj1 = get_org_act_obj(obj1);
	if (likely(obj2 != NULL))
		obj2 = get_org_act_obj(obj2);
	return obj1 == obj2;
}
EXPORT_SYMBOL(ts_cmp_ptrs);

/* unsafe assign ptr does not check for types*/
void _ts_assign_pointer_unsafe(void **p_ptr, void *obj)
{
	if (likely(obj != NULL))
		obj = get_org_act_obj(obj);
	*p_ptr = obj;
}
EXPORT_SYMBOL(_ts_assign_pointer_unsafe);

void _ts_assign_pointer(ts_thread_struct_t *self, void **p_ptr, void *obj)
{
	ts_obj_hdr_t *ohdr;
	ts_ptr_set_t *tx_alloc_set;
	ts_assign_ptr_set_t *tx_assign_set;
	void *enc_obj;
	int index = -1;

	if (unlikely(obj == NULL)) {
		*p_ptr = obj;
		return;
	}
	ohdr = obj_to_obj_hdr(obj);
	if (ohdr->type != TYPE_NEW) {
		obj = get_org_act_obj(obj);
		/* encoded the pointer before assignment*/
		enc_obj = encode_ptr(obj, obj_to_obj_hdr(obj)->ptr_tag);
		*p_ptr = enc_obj;
		//*p_ptr = obj;
		return;
	}
	ts_assert(ohdr->type == TYPE_NEW);
	/* check if obj is already in tx_alloc_set*/
	tx_alloc_set = &self->tx_alloc_set;
	tx_assign_set = &self->tx_assign_set;
	index = ptrset_get_index(tx_alloc_set, obj);
	/* obj not present*/
	if (index < 0) {
		/* enque obj in tx_alloc_set*/
		index = _ptrset_push(tx_alloc_set, obj);
		ts_trace(TS_DEBUG, "obj %p added to alloc_set\n", obj);
	}
	ts_assert(index >= 0);
	/* enque p_ptr and index in tx_assign_set*/
	assign_ptrset_push(tx_assign_set, p_ptr, index);
	/* p_ptr will be modified in ts_commit to point to nv_obj*/
	ts_trace(TS_DEBUG, "ts_assing_ptr: %p -> %p\n", p_ptr, obj);
	*p_ptr = obj;
	return;
}
EXPORT_SYMBOL(_ts_assign_pointer);

void ts_flush_log(ts_thread_struct_t *self)
{
	tvlog_flush(&self->tvlog, &self->ckptlog, &self->ckptlog_replica);
	ckptlog_flush(&self->ckptlog, &self->ckptlog_replica);
}
EXPORT_SYMBOL(ts_flush_log);

void ts_set_op(ts_thread_struct_t *self, unsigned long op_type)
{
	self->op_info.curr = 0;
	self->op_info.op_entry.op_type = op_type;
}
EXPORT_SYMBOL(ts_set_op);

void *ts_alloc_operand(ts_thread_struct_t *self, int size)
{
	void *tgt;

	tgt = self->op_info.op_entry.opd + self->op_info.curr;
	self->op_info.curr += size;
	ts_assert(self->op_info.curr <= TS_MAX_OPERAND_SIZE);
	return tgt;
}
EXPORT_SYMBOL(ts_alloc_operand);

void ts_memcpy_operand(ts_thread_struct_t *self, void *opd, int size)
{
	void *tgt;

	tgt = ts_alloc_operand(self, size);
	memcpy(tgt, opd, size);
}
EXPORT_SYMBOL(ts_memcpy_operand);

int ts_isolation_supported(int isolation)
{
	switch (isolation) {
	case TS_SNAPSHOT:
		return 1;
#ifdef TS_ENABLE_SERIALIZABILITY_LINEARIZABILITY
	case TS_SERIALIZABILITY:
		return 1;
	case TS_LINEARIZABILITY:
		return 1;
#endif
	}
	return 0;
}
EXPORT_SYMBOL(ts_memcpy_operand);
