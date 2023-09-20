#include "timestone.h"
#include "timestone_i.h"
#include "port.h"
#include "util.h"
#include "debug.h"
#include "clock.h"
#include "tvlog.h"
#include "ckptlog.h"
#include "oplog.h"
#include "qp.h"

static ts_qp_thread_t g_qp_thread ____cacheline_aligned2;
#ifdef TS_ENABLE_MOBJ_REPLICATION
static int n_ent_per_q[N_IO_URING_INST_MAX];
static int g_n_threads;
static int g_n_workers;
static int g_th_per_worker;
static int g_n_io_uring_inst;
static bool g_fd_flush_list[TN_FILES];
#endif

/*
 * thread list manipulation
 */
static ts_thread_list_t g_live_threads ____cacheline_aligned2;
static ts_thread_list_t g_zombie_threads ____cacheline_aligned2;

#define list_to_thread(__list)                                                 \
	({                                                                     \
		void *p = (void *)(__list);                                    \
		void *q;                                                       \
		q = p - ((size_t) & ((ts_thread_struct_t *)0)->list);          \
		(ts_thread_struct_t *)q;                                       \
	})

#define thread_list_for_each_safe(tl, pos, n, thread)                          \
	for (pos = (tl)->list.next, n = (pos)->next,                           \
	    thread = list_to_thread(pos);                                      \
	     pos != &(tl)->list;                                               \
	     pos = n, n = (pos)->next, thread = list_to_thread(pos))

static inline int thread_list_has_waiter(ts_thread_list_t *tl)
{
	return tl->thread_wait;
}

static inline void init_thread_list(ts_thread_list_t *tl)
{
	port_spin_init(&tl->lock);

	tl->cur_tid = 0;
	tl->num = 0;
	init_ts_list(&tl->list);
}

static inline void thread_list_destroy(ts_thread_list_t *tl)
{
	port_spin_destroy(&tl->lock);
}

static inline void thread_list_lock(ts_thread_list_t *tl)
{
	/* Lock acquisition with a normal priority */
	port_spin_lock(&tl->lock);
}

static inline void thread_list_lock_force(ts_thread_list_t *tl)
{
	/* Lock acquisition with a high priority
	 * which turns on the thread_wait flag
	 * so a lengthy task can stop voluntarily
	 * stop and resume later. */
	if (!port_spin_trylock(&tl->lock)) {
		smp_cas(&tl->thread_wait, 0, 1);
		port_spin_lock(&tl->lock);
	}
}

static inline void thread_list_unlock(ts_thread_list_t *tl)
{
	if (tl->thread_wait)
		smp_atomic_store(&tl->thread_wait, 0);
	port_spin_unlock(&tl->lock);
}

static inline void thread_list_add(ts_thread_list_t *tl,
				   ts_thread_struct_t *self)
{
	thread_list_lock_force(tl);
	{
		self->tid = tl->cur_tid++;
		tl->num++;
		ts_list_add(&self->list, &tl->list);
	}
	thread_list_unlock(tl);
}

static inline void thread_list_del_unsafe(ts_thread_list_t *tl,
					  ts_thread_struct_t *self)
{
	tl->num--;
	ts_list_del(&self->list);
	self->list.prev = self->list.next = NULL;
}

static inline void thread_list_del(ts_thread_list_t *tl,
				   ts_thread_struct_t *self)
{
	thread_list_lock_force(tl);
	{
		thread_list_del_unsafe(tl, self);
	}
	thread_list_unlock(tl);
}

static inline void thread_list_rotate_left_unsafe(ts_thread_list_t *tl)
{
	/* NOTE: A caller should hold a lock */
	ts_list_rotate_left(&tl->list);
}

static inline int thread_list_empty(ts_thread_list_t *tl)
{
	int ret;

	thread_list_lock_force(tl);
	{
		ret = ts_list_empty(&tl->list);
	}
	thread_list_unlock(tl);

	return ret;
}

/*
 * System clock functions
 */
static inline void advance_qp_clock(ts_sys_clks_t *clks, unsigned long qp0_clk)
{
	clks->__qp2 = clks->__qp1;
	clks->__qp1 = clks->__qp0;
	clks->__qp0 = qp0_clk;
}

#ifdef TS_ENABLE_MOBJ_REPLICATION
bool *get_drain_ptr(void)
{
	return (void *)&g_qp_thread.wait_for_drain;
}
#endif

/*
 * Quiescent detection functions
 */

static void qp_init(ts_qp_thread_t *qp_thread, unsigned long qp_clk)
{
	ts_thread_struct_t *thread;
	ts_list_t *pos, *n;

	thread_list_lock(&g_live_threads);
	{
		smp_mb();
		thread_list_for_each_safe (&g_live_threads, pos, n, thread) {
			thread->qp_info.run_cnt = thread->run_cnt;
			thread->qp_info.need_wait =
				thread->qp_info.run_cnt & 0x1;
		}
	}
	thread_list_unlock(&g_live_threads);
}

#ifdef TS_ENABLE_MOBJ_REPLICATION
static void check_for_drain_req(ts_qp_thread_t *qp_thread)
{
	if (smp_atomic_load(&qp_thread->wait_for_drain))
		smp_atomic_store(&qp_thread->wait_for_drain, false);
}
#endif

static void qp_wait(ts_qp_thread_t *qp_thread, unsigned long qp_clk,
		    bool need_io_poll)
{
	ts_thread_struct_t *thread;
	ts_list_t *pos, *n;

retry:
	thread_list_lock(&g_live_threads);
	{
		thread_list_for_each_safe (&g_live_threads, pos, n, thread) {
			if (!thread->qp_info.need_wait)
				continue;

			while (1) {
				/* Check if a thread passed quiescent period. */
				if (thread->qp_info.run_cnt !=
					    thread->run_cnt ||
				    gte_clock(thread->local_clk, qp_clk)) {
					thread->qp_info.need_wait = 0;
					break;
				}

				/* If a thread is waiting for adding or deleting
				 * from/to the thread list, yield and retry. */
				if (thread_list_has_waiter(&g_live_threads)) {
					thread_list_unlock(&g_live_threads);
					goto retry;
				}

				port_cpu_relax_and_yield();
				smp_mb();
			}
		}
	}
	thread_list_unlock(&g_live_threads);
}

static void qp_take_nap(ts_qp_thread_t *qp_thread)
{
	port_initiate_nap(&qp_thread->cond_mutex, &qp_thread->cond,
			  TS_QP_INTERVAL_USEC);
}

#ifdef TS_ENABLE_MOBJ_REPLICATION
static void _qp_cleanup_ckptlogs(ts_qp_thread_t *qp_thread)
{
	ts_thread_struct_t *thread;
	ts_list_t *pos, *n;
	unsigned long until_clk;

	until_clk = correct_qp_clock(qp_thread->clks.__min_ckpt_reclaimed);

	//	thread_list_lock(&g_live_threads);
	//	{
	thread_list_for_each_safe (&g_live_threads, pos, n, thread) {
		/* Free original masters and their volatile headers */
		/* ckptlog_cleanup will internally cleanup the replica as well*/
		ckptlog_cleanup(&thread->ckptlog, until_clk);
	}
	//	}
	//	thread_list_unlock(&g_live_threads);
}
#endif

static void qp_cleanup_ckptlogs(ts_qp_thread_t *qp_thread)
{
	ts_thread_struct_t *thread;
	ts_list_t *pos, *n;
	unsigned long until_clk;

	until_clk = correct_qp_clock(qp_thread->clks.__min_ckpt_reclaimed);

	thread_list_lock(&g_live_threads);
	{
		thread_list_for_each_safe (&g_live_threads, pos, n, thread) {
			/* Free original masters and their volatile headers */
			/* ckptlog_cleanup will internally cleanup the replica as well*/
			ckptlog_cleanup(&thread->ckptlog, until_clk);
		}
	}
	thread_list_unlock(&g_live_threads);
}

#ifdef TS_ENABLE_MOBJ_REPLICATION

static bool init_work_data(ts_qp_thread_t *qp_thread)
{
	ts_thread_struct_t *thread;
	ts_list_t *pos, *n;
	ts_thread_struct_t *pp_thread[g_n_threads];
	int th_cnt = 0, wrk_cnt = 0, j = 0, i = 0;
	bool need_init = true;

	thread_list_lock(&g_live_threads);
	{
		thread_list_for_each_safe (&g_live_threads, pos, n, thread) {
			pp_thread[th_cnt] = thread;
			++th_cnt;
			if (th_cnt > g_n_threads) {
				perror("error thread init in qp\n");
				ts_trace(TS_INFO, "th_cnt= %d\n", th_cnt);
				exit(0);
			}
		}
	}
	thread_list_unlock(&g_live_threads);
	if (th_cnt != g_n_threads) {
		ts_trace(TS_DEBUG, "th_cnt= %d\n =======================\n",
			 th_cnt);
		return need_init;
	}
	if (th_cnt == g_n_threads) {
		ts_trace(TS_DEBUG,
			 " !!!!! IO worker thread data initialized !!!!!!! \n");
	}
	for (i = 0; i < g_n_workers; ++i) {
		ts_trace(TS_DEBUG, "thread %d \n", i);
		for (j = 0; j < g_th_per_worker; ++j) {
			qp_thread->work_data[i].thread[j] = pp_thread[wrk_cnt];
			wrk_cnt += 1;
			ts_trace(TS_DEBUG, "thread[%d] %p\n", j,
				 qp_thread->work_data[i].thread[j]);
		}
	}
	need_init = false;
	return need_init;
}

static void poll_io_reqs_no_drain(io_work *wrk)
{
	int ret;
	struct io_uring_cqe *cqe;
	unsigned int n_io_req = *wrk->n_disk_entries;

	/* return if the io_uring
	 * buffers are empty*/
	if (!n_io_req)
		return;

	/* poll the io_uring queue for the completion*/
	for (unsigned int i = 0; i < n_io_req; ++i) {
		ret = io_uring_wait_cqe(wrk->ring, &cqe);
		if (ret < 0) {
			fprintf(stderr, "Error waiting for completion: %s\n",
				strerror(-ret));
		}
		io_uring_cqe_seen(wrk->ring, cqe);
		//		++wrk->n_req_comp;
	}
	ts_trace(TS_DEBUG, "n_disk_entries= %u\n", *wrk->n_disk_entries);
	ts_trace(TS_DEBUG, "n_io_req= %u\n", n_io_req);
	*wrk->n_disk_entries = *wrk->n_disk_entries - n_io_req;
	ts_trace(TS_DEBUG, "n_disk_entries(poll end)= %u\n",
		 *wrk->n_disk_entries);
}

static void prep_and_submit_io_reqs(io_work *wrk)
{
	int head, tail;
	int f_id, s_id, fd_index;
	uint64_t disk_offset;
	struct io_uring_sqe *sqe;
	unsigned long clk, qp_clk;
	ts_disk_entry_t entry;
	ts_thread_struct_t *thread;
	bool is_drain = false;
	bool need_flush;
	struct io_uring *ring;

	qp_clk = wrk->qp_clk;
	for (int i = 0; i < g_th_per_worker; ++i) {
		thread = wrk->thread[i];

		/* skip if the thread is a zombie, qp thread will 
		 * take care of these threads*/
		if (thread->live_status == THREAD_LIVE_ZOMBIE)
			continue;
		/* get the head and tail pointer for 
		* the replica buffer*/
		head = smp_atomic_load(&thread->rs_head);
		tail = smp_atomic_load(&thread->rs_tail);

		/* if the buffer is empty move on 
		* to the next thread*/
		if (head == tail || tail < 0)
			continue;

		while (head != tail) {
			head = (head + 1) % MAX_SET_SIZE;
			/* check if the commit_clk is less than qp0*/
			clk = thread->tx_replica_set[head].commit_clk;
			if (gt_clock(clk, qp_clk)) {
				/* if commit_clk > qp0_clk means this object
				* does belong to the current qp so break
				* all the following entries will also be the same
				* these entries will be taken care off 
				* in the next qp cycle*/

				/* TODO: see if this part needs optimization?
				* instead of breaking, may be submit to a separate io_uring
				* instance that takes care off entries that are outside of the
				* current qp detection window?*/

				/* we do not have to consider clock constraints while draining the
				* io_uring buffers, draining only happens when all the app threads
				* have terminated or zombinized*/
				if (!is_drain) {
					++wrk->n_skip;
					break;
				}
			}

			/* get io_uring entry*/
			ring = wrk->ring;
		retry:
			sqe = io_uring_get_sqe(ring);
			if (!sqe) {
				ts_trace(TS_DEBUG, "could not get SQE \n");
				ts_trace(TS_DEBUG, "ring= %u\n",
					 *wrk->n_disk_entries);
				poll_io_reqs_no_drain(wrk);
				ts_trace(TS_DEBUG, "ring(retry)= %u\n",
					 *wrk->n_disk_entries);
				goto retry;
			}
			/* prepare the io_uring entry to 
			* trigger the disk write*/
			entry = thread->tx_replica_set[head];
			s_id = thread->socket_id;
			f_id = get_disk_file_id(entry.offset);
			fd_index = get_fd_index(s_id, f_id);
			disk_offset = get_disk_offset(entry.offset);
			ts_trace(
				TS_DEBUG,
				"n_off= %ld\t d_off= %ld\t f_id= %d\t f_ind= %d\n",
				entry.offset, disk_offset, f_id, fd_index);

			/* using global list to keep track of written fds*/
			if ((need_flush = smp_atomic_load(
				     &g_fd_flush_list[fd_index])) == false)
				smp_atomic_store(&g_fd_flush_list[fd_index],
						 true);

			io_uring_prep_write(sqe, fd_index, entry.src, entry.len,
					    disk_offset);
			sqe->flags |= IOSQE_FIXED_FILE;
			io_uring_submit(ring);
			stat_thread_acc(thread, n_disk_write_bytes, entry.len);
			++(*wrk->n_disk_entries);
			smp_atomic_store(&thread->rs_head, head);
		} /* while loop*/

	} /* for loop*/
}

static void flush_disk_cache_wrk(io_work *wrk)
{
	int id, start, end;

	id = wrk->w_id;
	start = id * g_n_workers;
	end = start + (TN_FILES / g_n_workers);

	for (int i = start; i < end; ++i) {
		if (!g_fd_flush_list[i])
			continue;
		fdatasync(wrk->fd[i]);
		++wrk->n_sync;
	}
}

static void poll_io_reqs_for_completion(io_work *wrk)
{
	int ret;
	struct io_uring_cqe *cqe;
	unsigned int n_io_req = *wrk->n_disk_entries;

	/* return if the io_uring
	 * buffers are empty*/
	if (!n_io_req)
		return;

	/* poll the io_uring queue for the completion*/
	for (unsigned int i = 0; i < n_io_req; ++i) {
		ret = io_uring_wait_cqe(wrk->ring, &cqe);
		if (ret < 0) {
			fprintf(stderr, "Error waiting for completion: %s\n",
				strerror(-ret));
		}
		io_uring_cqe_seen(wrk->ring, cqe);
		++wrk->n_req_comp;
	}
	flush_disk_cache_wrk(wrk);
}

static void reset_flush(io_work *wrk)
{
	size_t size = N_SOCKET * _N_DISK_FILES * sizeof(bool);

	memset(wrk->flush_fd, 0, size);
}

static void *io_uring_main(void *arg)
{
	io_work *wrk = arg;

	//reset_flush(wrk);
	prep_and_submit_io_reqs(wrk);
	poll_io_reqs_for_completion(wrk);
	return NULL;
}

static void create_io_workers(ts_qp_thread_t *qp_thread, unsigned long qp_clk)
{
	int ret;

	for (int i = 0; i < g_n_workers; ++i) {
		/* update the clk info*/
		qp_thread->work_data[i].qp_clk = qp_clk;
		ret = pthread_create(&qp_thread->workers[i], NULL,
				     io_uring_main,
				     (void *)&qp_thread->work_data[i]);
		if (ret) {
			perror("Error creating IO workers\n");
			exit(0);
		}
	}
}

static void wait_for_io_workers(ts_qp_thread_t *qp_thread)
{
	int i = 0;

	for (i = 0; i < g_n_workers; ++i) {
		printf("waiting for worker %d\n", i);
		if (pthread_join(qp_thread->workers[i], NULL) != 0) {
			ts_trace(TS_INFO, "IO worker %d unable to join\n", i);
			ts_trace(TS_INFO, "id= %d \n", i);
			exit(0);
		}
		//		pthread_detach(qp_thread->wrk[i]);
	}
	printf("======================================\n");
}

static bool write_to_disk_async(ts_qp_thread_t *qp_thread,
				unsigned long qp0_clk, unsigned char need_free)
{
	bool is_submitted = false;
	unsigned int n_reqs_sub = 0, n_reqs_comp = 0, n_sync = 0;
	bool need_init;
	int ret;

	if (unlikely(qp_thread->need_th_data_init)) {
		need_init = init_work_data(qp_thread);
		qp_thread->need_th_data_init = need_init;
	}

	/* application threads are not 
	 * ready yet*/
	if (qp_thread->need_th_data_init)
		return is_submitted;

	/* reset the global flush list to false*/
	memset(g_fd_flush_list, 0, TN_FILES * sizeof(bool));
	thread_list_lock(&g_live_threads);
	{
		/* spawn workers*/
		create_io_workers(qp_thread, qp0_clk);

		/* If we reclaimed ckptlog, free the master 
		 * and its vheader while waiting for workers to finish*/
		if (need_free)
			_qp_cleanup_ckptlogs(qp_thread);

		//		wait_for_io_workers(qp_thread);
		for (int i = 0; i < g_n_workers; ++i) {
			ts_trace(TS_DEBUG, "waiting for worker %d\n", i);
			ret = pthread_join(qp_thread->workers[i], NULL);
			if (ret != 0) {
				ts_trace(TS_INFO,
					 "Error waiting for IO worker %d \n",
					 i);
			}
			pthread_detach(qp_thread->workers[i]);
			ts_trace(TS_DEBUG, "worker %d joined\n", i);
		}
	}
	thread_list_unlock(&g_live_threads);

	/* collect the disk write statistics*/
	for (int i = 0; i < g_n_workers; ++i) {
		n_reqs_sub += qp_thread->n_disk_entries[i];
		n_reqs_comp += qp_thread->work_data[i].n_req_comp;
		n_sync += qp_thread->work_data[i].n_sync;
		n_ent_per_q[i] += qp_thread->n_disk_entries[i];
		qp_thread->n_skip += qp_thread->work_data[i].n_skip;
		/* reset the count*/
		qp_thread->n_disk_entries[i] = 0;
		qp_thread->work_data[i].n_skip = 0;
		qp_thread->work_data[i].n_req_comp = 0;
		qp_thread->work_data[i].n_sync = 0;
	}
	stat_qp_acc(qp_thread, n_fdsync, n_sync);
	qp_thread->n_disk_writes += n_reqs_sub;
	if (n_reqs_sub != n_reqs_comp) {
		ts_trace(TS_INFO,
			 "IO error: n_reqs_sub= %d \t n_reqs_comp= %d\n",
			 n_reqs_sub, n_reqs_comp);
	}
	ts_trace(TS_DEBUG, "n_reqs_sub= %d \t n_reqs_comp= %d\n", n_reqs_sub,
		 n_reqs_comp);
	ts_trace(TS_DEBUG, "======================================\n");
	return is_submitted;
}

#endif

static void qp_detect(ts_qp_thread_t *qp_thread, unsigned char need_free)
{
	unsigned long qp0_clk;
	bool need_io_poll = false;

	/* Init qp */
	qp0_clk = get_clock();
	qp_init(qp_thread, qp0_clk);
	stat_qp_inc(qp_thread, n_qp_detect);

#ifdef TS_ENABLE_MOBJ_REPLICATION
	write_to_disk_async(qp_thread, qp0_clk, need_free);
	check_for_drain_req(qp_thread);
#endif

#ifndef TS_ENABLE_MOBJ_REPLICATION
	/*If we reclaimed ckptlog, free the master and its vheader. */
	if (need_free) {
		qp_cleanup_ckptlogs(qp_thread);
	}
#endif

	/* If not urgent, take a nap */
	if (!qp_thread->reclaim.requested) {
		qp_take_nap(qp_thread);
		stat_qp_inc(qp_thread, n_qp_nap);
	}

	/* Wait until quiescent state */
	qp_wait(qp_thread, qp0_clk, need_io_poll);
	qp0_clk = correct_qp_clock(qp0_clk);
	advance_qp_clock(&qp_thread->clks, qp0_clk);
}

static void qp_help_reclaim_log(ts_qp_thread_t *qp_thread)
{
#ifdef TS_ENABLE_HELP_RECLAIM
	ts_thread_struct_t *thread;
	ts_list_t *pos, *n;

retry:
	thread_list_lock(&g_live_threads);
	{
		smp_mb();
		thread_list_for_each_safe (&g_live_threads, pos, n, thread) {
			/* If a thread is waiting for adding or deleting
			 * from/to the thread list, yield and retry. */
			if (thread_list_has_waiter(&g_live_threads)) {
				thread_list_unlock(&g_live_threads);
				goto retry;
			}

			/* Help reclaiming */
			if (unlikely(thread->reclaim.requested)) {
				if (thread->reclaim.tvlog)
					tvlog_reclaim(&thread->tvlog,
						      &thread->ckptlog,
						      &thread->ckptlog_replica);
				if (thread->reclaim.ckptlog)
					ckptlog_reclaim(
						&thread->ckptlog,
						&thread->ckptlog_replica);
			}
		}

		/* Rotate the thread list counter clockwise for fairness. */
		thread_list_rotate_left_unsafe(&g_live_threads);
	}
	thread_list_unlock(&g_live_threads);
#endif
}

#ifdef TS_ENABLE_MOBJ_REPLICATION
static void flush_to_disk(ts_qp_thread_t *qp_thread)
{
	for (int i = 0; i < TN_FILES; ++i) {
		if (!qp_thread->flush_fd[i])
			continue;
		fdatasync(qp_thread->fd[i]);
		stat_qp_inc(qp_thread, n_fdsync);
	}
}

static int wait_for_disk_writes(void *arg)
{
	ts_qp_thread_t *qp_thread = arg;
	int n_req_sub = 0, ret, cnt = 0;
	struct io_uring_cqe *cqe;

	/* get the total no of entries submitted to 
	 * each io_uring buffer*/
	for (int i = 0; i < g_n_io_uring_inst; ++i) {
		n_req_sub += qp_thread->n_disk_entries[i];
	}

	/* poll each of the io_uring buffer 
	 * for the completion*/
	for (int i = 0; i < g_n_io_uring_inst; ++i) {
		/* skip the empty buffers*/
		if (!qp_thread->n_disk_entries[i])
			continue;
		for (unsigned int j = 0; j < qp_thread->n_disk_entries[i];
		     ++j) {
			ret = io_uring_wait_cqe(&qp_thread->ring[i], &cqe);
			if (ret < 0) {
				fprintf(stderr,
					"Error waiting for completion: %s\n",
					strerror(-ret));
				return ret;
			}
			io_uring_cqe_seen(&qp_thread->ring[i], cqe);
			++cnt;
		}
		//		ts_trace(TS_INFO, "completion cnt= %d\n", cnt);
		/* TODO: cleanup*/
		n_ent_per_q[i] += qp_thread->n_disk_entries[i];
		/* reset the count*/
		qp_thread->n_disk_entries[i] = 0;
	}
	return cnt;
}

static int prep_io_uring_reqs(ts_qp_thread_t *qp_thread,
			      ts_thread_struct_t *thread, unsigned long qp_clk,
			      bool is_drain)
{
	int head, tail;
	int run_cnt = 0, ret, n_current;
	int f_id, r_id, s_id, fd_index;
	uint64_t disk_offset;
	struct io_uring_sqe *sqe;
	unsigned long clk;
	ts_disk_entry_t entry;
	unsigned int old_cnt = qp_thread->n_disk_writes;

	/* get the head and tail pointer for 
	 * the replica buffer*/
	head = smp_atomic_load(&thread->rs_head);
	tail = smp_atomic_load(&thread->rs_tail);

	/* if the buffer is empty move on 
	 * to the next thread*/
	if (head == tail || tail < 0)
		return 0;

	while (head != tail) {
		head = (head + 1) % MAX_SET_SIZE;
		/* check if the commit_clk is less than qp0*/
		clk = thread->tx_replica_set[head].commit_clk;
		if (gt_clock(clk, qp_clk)) {
			/* if commit_clk > qp0_clk means this object
			 * does belong to the current qp so break
			 * all the following entries will also be the same
			 * these entries will be taken care off 
			 * in the next qp cycle*/

			/* TODO: see if this part needs optimization?
			 * instead of breaking, may be submit to a separate io_uring
			 * instance that takes care off entries that are outside of the
			 * current qp detection window?*/

			/* we do not have to consider clock constraints while draining the
			 * io_uring buffers, draining only happens when all the app threads
			 * have terminated or zombinized*/
		}

	retry:
		/* get io_uring entry*/
		r_id = qp_thread->n_disk_writes % g_n_io_uring_inst;
		sqe = io_uring_get_sqe(&qp_thread->ring[r_id]);
		if (!sqe) {
			//	fprintf(stderr, "could not get SQE \n");
			/* TODO: if SQ ring is full poll on completion 
			* and then start preparing the request*/
			n_current = 0;
			for (int i = 0; i < g_n_io_uring_inst; ++i) {
				n_current += qp_thread->n_disk_entries[i];
				//		ts_trace(TS_INFO, "ring[%d]= %d\n", i , qp_thread->n_disk_entries[i]);
			}
			/* wait for writes to finish*/
			ret = wait_for_disk_writes(qp_thread);
			if (ret != n_current) {
				ts_trace(
					TS_INFO,
					"n_entries_polled= %d \t  n_entries_submitted= %d\n",
					ret, n_current);
				perror("Error polling finished reqs\n");
			}
			goto retry;
		}
		/* prepare the io_uring entry to 
		 * trigger the disk write*/
		entry = thread->tx_replica_set[head];
		s_id = thread->socket_id;
		f_id = get_disk_file_id(entry.offset);
		fd_index = get_fd_index(s_id, f_id);
		disk_offset = get_disk_offset(entry.offset);
		if (!qp_thread->flush_fd[fd_index])
			qp_thread->flush_fd[fd_index] = true;

		io_uring_prep_write(sqe, fd_index, entry.src, entry.len,
				    disk_offset);
		sqe->flags |= IOSQE_FIXED_FILE;
		io_uring_submit(&qp_thread->ring[r_id]);
		++run_cnt;
		stat_thread_acc(thread, n_disk_write_bytes, entry.len);
		++qp_thread->n_disk_entries[r_id];
		++qp_thread->n_file_writes[fd_index];
		++qp_thread->n_disk_writes;
		smp_atomic_store(&thread->rs_head, head);
	}
	if (old_cnt == qp_thread->n_disk_writes)
		return 0;
	run_cnt = (qp_thread->n_disk_writes - old_cnt);
	//	ts_trace(TS_INFO, "run_cnt= %d\n", run_cnt);
	return run_cnt;
}
#endif

static void qp_reap_zombie_threads(ts_qp_thread_t *qp_thread)
{
	ts_thread_struct_t *thread;
	ts_list_t *pos, *n;
#ifdef TS_ENABLE_MOBJ_REPLICATION
	bool is_drain = true;
	int cnt, n_reqs_sub = 0;
#endif

retry:
	thread_list_lock(&g_zombie_threads);
	{
		smp_mb();
		thread_list_for_each_safe (&g_zombie_threads, pos, n, thread) {
			/* If a thread is waiting for adding or deleting
			 * from/to the thread list, yield and retry. */
			if (thread_list_has_waiter(&g_zombie_threads)) {
				thread_list_unlock(&g_zombie_threads);
				goto retry;
			}

			/* Propagate the system clock */
			thread->clks = qp_thread->clks;

			/* Enforce reclaiming logs */
			if (tvlog_used(&thread->tvlog)) {
				*thread->tvlog.need_reclaim =
					RECLAIM_TVLOG_CKPT;
				tvlog_reclaim(&thread->tvlog, &thread->ckptlog,
					      &thread->ckptlog_replica);
			}

			if (ckptlog_used(&thread->ckptlog)) {
				*thread->ckptlog.need_reclaim =
					RECLAIM_CKPTLOG_WRITEBACK_ALL;
				ckptlog_reclaim(&thread->ckptlog,
						&thread->ckptlog_replica);
			}

			/* If the log is completely reclaimed, try next thread */
			if (tvlog_used(&thread->tvlog) == 0 &&
			    ckptlog_used(&thread->ckptlog) == 0) {
				tvtlog_destroy(&thread->tvlog);
				ckptlog_destroy(&thread->ckptlog,
						&thread->ckptlog_replica);
				oplog_destroy(&thread->oplog,
					      &thread->oplog_replica);

#ifdef TS_ENABLE_MOBJ_REPLICATION
				/* submit all the pending writes in the replica set for disk
				 * replication before freeing the thread*/
				cnt = prep_io_uring_reqs(qp_thread, thread,
							 qp_thread->clks.__qp0,
							 is_drain);
				if (cnt) {
					/* submitted reqs will be polled for completion 
					 * before destroying qp_thread*/
					//submit_io_uring_reqs(qp_thread);
					n_reqs_sub = cnt;
					cnt = wait_for_disk_writes(qp_thread);
					if (cnt != n_reqs_sub) {
						ts_trace(
							TS_INFO,
							"n_entries_polled= %d \t  n_entries_submitted= %d\n",
							cnt, n_reqs_sub);
						perror("Zombie:Error polling finished reqs\n");
					}
					/* flush all writes to disk
					 * once logs are destroyed there is no way 
					 * to recover the writes*/
					flush_to_disk(qp_thread);
				}
#endif
				/* If it is a dead zombie, reap */
				if (thread->live_status == THREAD_DEAD_ZOMBIE) {
					thread_list_del_unsafe(
						&g_zombie_threads, thread);
					ts_thread_free(thread);
				}
			}
		}
	}
	thread_list_unlock(&g_zombie_threads);
}

static void qp_reclaim_barrier(ts_qp_thread_t *qp_thread)
{
	ts_thread_struct_t *thread;
	ts_list_t *pos, *n;
	unsigned long min_ckpt_reclaimed;

retry:
	min_ckpt_reclaimed = qp_thread->clks.__min_ckpt_reclaimed;
	thread_list_lock(&g_live_threads);
	{
		smp_mb();
		thread_list_for_each_safe (&g_live_threads, pos, n, thread) {
			/* Did we finish reclaiming? */
			if (thread->reclaim.requested) {
				thread_list_unlock(&g_live_threads);
				port_cpu_relax_and_yield();
				goto retry;
			}
			/* Update the minimum reclaimed ckpt timestamp */
			if (thread->clks.__min_ckpt_reclaimed <
			    min_ckpt_reclaimed) {
				min_ckpt_reclaimed =
					thread->clks.__min_ckpt_reclaimed;
			}
		}

		/* Now update the minimum timestamp of all reclaimed ckpt
		 * to decide until when we can free original masters. */
		qp_thread->clks.__min_ckpt_reclaimed = min_ckpt_reclaimed;
	}
	thread_list_unlock(&g_live_threads);
}

static void qp_trigger_reclaim(ts_qp_thread_t *qp_thread, ts_reclaim_t reclaim)
{
	ts_thread_struct_t *thread;
	ts_list_t *pos, *n;

	/* Check if at least one QP passed after the last reclamation. */
	ts_assert(lt_clock(qp_thread->clks.__last_ckpt, qp_thread->clks.__qp0));

	/* For each thread ... */
	thread_list_lock(&g_live_threads);
	{
		ts_trace(
			TS_QP,
			"[QP:%ld/%ld/%ld] ===== Log reclamation triggered: %s, %s =====\n",
			qp_thread->clks.__qp0, qp_thread->clks.__last_ckpt,
			qp_thread->clks.__min_ckpt_reclaimed,
			req2str(reclaim.tvlog), req2str(reclaim.ckptlog));

		/* For each live threads ... */
		thread_list_for_each_safe (&g_live_threads, pos, n, thread) {
			/* Check if the previous reclamation finished. */
			ts_assert(thread->reclaim.requested == 0);

			/* Propagate the system clock */
			thread->clks = qp_thread->clks;

			/* ... and then copy the reclamation requests.
			 * We should use the copy of qp_thread->reclaim, *reclaim,
			 * because qp_thread->reclaim could be updated while
			 * we are triggering reclaim. */
			smp_wmb_tso();
			thread->reclaim = reclaim;
		}
	}
	thread_list_unlock(&g_live_threads);
	smp_mb();
}

static inline int should_stop(ts_qp_thread_t *qp_thread)
{
	return qp_thread->stop_requested &&
	       thread_list_empty(&g_zombie_threads) &&
	       thread_list_empty(&g_live_threads);
}

static void __qp_thread_main(void *arg)
{
	ts_qp_thread_t *qp_thread = arg;
	unsigned char need_free;
	ts_reclaim_t reclaim;
	unsigned long last_ckpt_clk;

	/* Qp detection loop, which runs until stop is requested
	 * and all zombie threads are reclaimed after flushing
	 * all their logs. */
	need_free = 0;
	while (!should_stop(qp_thread)) {
		/* Detect QP and free act_vhdr if needed */
		qp_detect(qp_thread, need_free);
		need_free = 0;

		/* If a stop is requested, flush out all logs. */
		if (unlikely(qp_thread->stop_requested)) {
			request_tvlog_reclaim(RECLAIM_TVLOG_CKPT);
			request_ckptlog_reclaim(RECLAIM_CKPTLOG_WRITEBACK_ALL);
		}

		/* If a reclaim is not requested, go for another qp detection. */
		if (!qp_thread->reclaim.requested) {
			continue;
		}
		ts_trace(TS_QP,
			 "[QPT] Before Trigger %04x, %04x, %04x, %s, %s \n",
			 qp_thread->reclaim.requested, qp_thread->reclaim.tvlog,
			 qp_thread->reclaim.ckptlog,
			 req2str(qp_thread->reclaim.tvlog),
			 req2str(qp_thread->reclaim.ckptlog));

		/* Trigger reclaim if requested */
		reclaim.requested = smp_swap(&qp_thread->reclaim.requested, 0);
		ts_trace(TS_QP,
			 "[QPT] After Trigger %04x, %04x, %04x, %s, %s \n",
			 qp_thread->reclaim.requested, qp_thread->reclaim.tvlog,
			 qp_thread->reclaim.ckptlog,
			 req2str(qp_thread->reclaim.tvlog),
			 req2str(qp_thread->reclaim.ckptlog));

		ts_trace(
			TS_QP,
			"[QPT] After Trigger reclaim Local %04x, %04x, %04x, %s, %s \n",
			reclaim.requested, reclaim.tvlog, reclaim.ckptlog,
			req2str(reclaim.tvlog), req2str(reclaim.ckptlog));

		qp_trigger_reclaim(qp_thread, reclaim);

		/* Help reclamation */
		qp_reap_zombie_threads(qp_thread);
		qp_help_reclaim_log(qp_thread);

		/* Wait for a reclamation barrier */
		qp_reclaim_barrier(qp_thread);

		/* If a new checkpoint is created,
		 * update the last checkpoint timestamp. */
		if (reclaim.tvlog == RECLAIM_TVLOG_CKPT) {
			/* Persist ckpt clk first */
			last_ckpt_clk = qp_thread->clks.__qp0;
			nvlog_set_last_ckpt_clk(last_ckpt_clk);

			/* ... then make __last_ckpt public.*/
			qp_thread->clks.__last_ckpt = last_ckpt_clk;
		}

		/* If a checkpoint log is reclaimed,
		 * we need to free the original master objects
		 * freed after a reclamation barrier passed. */
		need_free = reclaim.ckptlog;
		smp_mb();

		/* Print out message */
		ts_trace(
			TS_QP,
			"[QP:%ld/%ld/%ld] ----- Reclamation barrier passed -----\n",
			qp_thread->clks.__qp0, qp_thread->clks.__last_ckpt,
			qp_thread->clks.__min_ckpt_reclaimed);
	}
}

static void *qp_thread_main(void *arg)
{
	__qp_thread_main(arg);
	return NULL;
}

static int init_qp_thread(ts_qp_thread_t *qp_thread)
{
	int rc;

	/* Zero out qp_thread and set __min_ckpt_reclaimed to infinite */
	memset(qp_thread, 0, sizeof(*qp_thread));
	qp_thread->clks.__last_ckpt = MIN_VERSION;
	qp_thread->clks.__min_ckpt_reclaimed = MAX_VERSION;

#ifdef TS_ENABLE_MOBJ_REPLICATION
	qp_thread->wait_for_drain = false;
	qp_thread->need_th_data_init = true;

	if (g_n_threads <= N_WORKERS_MAX)
		g_n_workers = g_n_threads;
	else
		g_n_workers = N_WORKERS_MAX;
	g_th_per_worker = g_n_threads / g_n_workers;
	g_n_io_uring_inst = g_n_workers;

	/*init io_uring queues*/
	rc = setup_io_uring(qp_thread->ring, g_n_io_uring_inst);
	if (rc) {
		ts_trace(TS_ERROR, "Error setting up IO_URING instances: %d\n",
			 rc);
		return rc;
	}
	get_disk_fds(qp_thread->fd);
	/* init wrk data*/
	if (!(qp_thread->workers = (pthread_t *)port_alloc(sizeof(pthread_t) *
							   g_n_workers))) {
		ts_trace(TS_INFO, "Error allocating workers\n");
		exit(0);
	}
	if (!(qp_thread->work_data =
		      (io_work *)port_alloc(sizeof(io_work) * g_n_workers))) {
		ts_trace(TS_INFO, "Error allocating workers data\n");
		exit(0);
	}
	memset(qp_thread->work_data, 0, sizeof(io_work) * g_n_workers);
	for (int i = 0; i < g_n_workers; ++i) {
		qp_thread->work_data[i].w_id = i;
		qp_thread->work_data[i].ring = &qp_thread->ring[i];
		qp_thread->n_disk_entries[i] = 0;
		qp_thread->work_data[i].n_disk_entries =
			&qp_thread->n_disk_entries[i];
		qp_thread->work_data[i].n_file_writes =
			qp_thread->n_file_writes;
		if (!(qp_thread->work_data[i].thread = (ts_thread_struct_t **)
			      port_alloc(sizeof(ts_thread_struct_t *) *
					 g_th_per_worker))) {
			ts_trace(TS_INFO, "Error allocating workers data\n");
			exit(0);
		}
		get_disk_fds(qp_thread->work_data[i].fd);
	}
#endif

	/* Init thread-related stuffs */
	port_cond_init(&qp_thread->cond);
	port_mutex_init(&qp_thread->cond_mutex);
	rc = port_create_thread("qp_thread", &qp_thread->thread,
				&qp_thread_main, qp_thread,
				&qp_thread->completion);
	if (rc) {
		ts_trace(TS_ERROR, "Error creating builder thread: %d\n", rc);
		return rc;
	}
	return 0;
}

static inline void wakeup_qp_thread(ts_qp_thread_t *qp_thread)
{
	port_initiate_wakeup(&qp_thread->cond_mutex, &qp_thread->cond);
}

static void finish_qp_thread(ts_qp_thread_t *qp_thread)
{
	smp_atomic_store(&qp_thread->stop_requested, 1);
	wakeup_qp_thread(qp_thread);

	port_wait_for_finish(&qp_thread->thread, &qp_thread->completion);
#ifdef TS_ENABLE_MOBJ_REPLICATION
	close_io_uring_instances(qp_thread->ring);
	for (int i = 0; i < g_n_io_uring_inst; ++i) {
		ts_trace(TS_QP, "ring[%d]= %d\n", i, n_ent_per_q[i]);
		port_free(qp_thread->work_data[i].thread);
	}
	port_free(qp_thread->workers);
	port_free(qp_thread->work_data);
#endif
	port_mutex_destroy(&qp_thread->cond_mutex);
	port_cond_destroy(&qp_thread->cond);
	stat_qp_merge(qp_thread);
}

static int _request_reclaim(volatile unsigned char *p_old_req,
			    unsigned char new_req)
{
	unsigned char old_req = *p_old_req;

	ts_trace(TS_QP, "[QP] status before request: %04x, %04x, %04x\n",
		 g_qp_thread.reclaim.requested, g_qp_thread.reclaim.tvlog,
		 g_qp_thread.reclaim.ckptlog);

	if (new_req > old_req && smp_cas(p_old_req, old_req, new_req)) {
		ts_trace(TS_QP, "[QP] %s requested!\n", req2str(new_req));
		ts_trace(TS_QP, "[QP] status after request: %04x, %04x, %04x\n",
			 g_qp_thread.reclaim.requested,
			 g_qp_thread.reclaim.tvlog,
			 g_qp_thread.reclaim.ckptlog);
		wakeup_qp_thread(&g_qp_thread);
		return 1;
	}
	return 0;
}

int request_tvlog_reclaim(unsigned char new_req)
{
	return _request_reclaim(&g_qp_thread.reclaim.tvlog, new_req);
}

int request_ckptlog_reclaim(unsigned char new_req)
{
	return _request_reclaim(&g_qp_thread.reclaim.ckptlog, new_req);
}

#ifdef TS_ENABLE_MOBJ_REPLICATION
static void update_thread_count(int n_threads)
{
	if (n_threads <= N_WORKERS_MAX) {
		g_n_threads = n_threads;
		return;
	}
	if (n_threads % N_WORKERS_MAX) {
		ts_trace(TS_INFO,
			 "invalid thread count, adjust the MAX workers\n");
		exit(0);
	}
	g_n_threads = n_threads;
}
#endif

int init_qp(int n_threads)
{
	int rc;

	init_thread_list(&g_live_threads);
	init_thread_list(&g_zombie_threads);
#ifdef TS_ENABLE_MOBJ_REPLICATION
	update_thread_count(n_threads);
#endif
	rc = init_qp_thread(&g_qp_thread);
	return rc;
}

void deinit_qp(void)
{
	ts_trace(TS_QP, "[QP] !!! Finishing the QP thread !!!\n");
#ifdef TS_ENABLE_MOBJ_REPLICATION
	ts_trace(TS_QP, "###### n_skip= %d ########\n", g_qp_thread.n_skip);
#endif
	finish_qp_thread(&g_qp_thread);
	thread_list_destroy(&g_live_threads);
	thread_list_destroy(&g_zombie_threads);
}

void register_thread(ts_thread_struct_t *self)
{
	thread_list_add(&g_live_threads, self);
}

void deregister_thread(ts_thread_struct_t *self)
{
	thread_list_del(&g_live_threads, self);
}

void zombinize_thread(ts_thread_struct_t *self)
{
	thread_list_add(&g_zombie_threads, self);
}

void reset_all_stats(void)
{
#ifdef TS_ENABLE_STATS
	ts_thread_struct_t *thread;
	ts_list_t *pos, *n;

	/* Reset stats for all zombie threads */
	thread_list_lock(&g_zombie_threads);
	{
		thread_list_for_each_safe (&g_zombie_threads, pos, n, thread) {
			memset(&thread->stat, 0, sizeof(thread->stat));
		}
	}
	thread_list_unlock(&g_zombie_threads);

	/* Reset stats for all live threads */
	thread_list_lock(&g_live_threads);
	{
		thread_list_for_each_safe (&g_live_threads, pos, n, thread) {
			memset(&thread->stat, 0, sizeof(thread->stat));
		}
	}
	thread_list_unlock(&g_live_threads);
#endif
}
