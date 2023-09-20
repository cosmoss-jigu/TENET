#ifndef _QP_H
#define _QP_H

#include "disk.h"
#include "timestone_i.h"
#ifdef __cplusplus
extern "C" {
#endif

#define QP_POLL_DONE 0x01
#define QP_POLL_READY 0x11
#define QP_POLL_STOP 0x10
#define QP_EXIT 0x00

int init_qp(int n_threads);
void deinit_qp(void);
void register_thread(ts_thread_struct_t *);
void deregister_thread(ts_thread_struct_t *);
void zombinize_thread(ts_thread_struct_t *);
int request_tvlog_reclaim(unsigned char);
int request_ckptlog_reclaim(unsigned char);
void reset_all_stats(void);
bool *get_drain_ptr(void);

#ifdef __cplusplus
}
#endif
#endif
