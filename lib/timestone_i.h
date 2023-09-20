#ifndef _TIMESTONE_I_H
#define _TIMESTONE_I_H

#include "arch.h"
#include "config.h"
#include "port.h"
#include "timestone.h"
#include <liburing.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_VERSION (ULONG_MAX - 1)
#define MIN_VERSION (0ul)
#define INVALID_GEN_ID (ULONG_MAX - 1)
#define CANARY_SIZE sizeof(uint64_t)
#define CHECKSUM_SIZE sizeof(uint32_t)
#define OHDR_CANARY_MASK sizeof(ts_act_hdr_struct_t)
#define OBJ_CANARY_MASK sizeof(ts_cpy_hdr_struct_t)
#define INVALID_PTR_TAG (ULLONG_MAX - 1)
#define INVALID_CHECKSUM (UINT32_MAX - 1)
#define ESPATIAL 200
#define ETEMPORAL 201
#define MAX_SET_SIZE 200000ul
#define _N_DISK_FILES 8
#define N_SOCKET 2
#define TN_FILES N_SOCKET *_N_DISK_FILES
#define N_IO_URING_ENTRIES 32000
#define N_IO_URING_INST_MAX 8
#define N_WORKERS_MAX 8
#define IO_URING_IDLE 256000
#define CHUNK_SIZE 16 * 1024 /* 16kb*/

#define STAT_NAMES                                                             \
  S(n_starts)                                                                  \
  S(n_finish)                                                                  \
  S(n_aborts)                                                                  \
  S(n_aborts_validation)                                                       \
  S(n_flush_new_act_bytes)                                                     \
  S(n_alloc_act_obj_bytes)                                                     \
  S(n_disk_write_bytes)                                                        \
  S(n_fdsync)                                                                  \
  S(n_tvlog_best_effort)                                                       \
  S(n_tvlog_ckpt)                                                              \
  S(n_tvlog_cpobj_written_bytes)                                               \
  S(n_tvlog_written_bytes)                                                     \
  S(n_tvlog_reclaimed_bytes)                                                   \
  S(n_tvlog_ckpt_bytes)                                                        \
  S(n_oplog_reclaim)                                                           \
  S(n_oplog_reclaimed_ops)                                                     \
  S(n_oplog_reclaimed_bytes)                                                   \
  S(n_oplog_written_bytes)                                                     \
  S(n_ckptlog_best_effort)                                                     \
  S(n_ckptlog_writeback)                                                       \
  S(n_ckptlog_reclaimed_bytes)                                                 \
  S(n_ckptlog_writeback_bytes)                                                 \
  S(n_qp_detect)                                                               \
  S(n_qp_nap)                                                                  \
  S(max__)
#define S(x) stat_##x,

enum { STAT_NAMES };

enum {
  TYPE_ACTUAL = 0,  /* actual object that is committed*/
  TYPE_WRT_SET,     /* log: write set header */
  TYPE_COPY,        /* log: copied version */
  TYPE_FREE,        /* log: copy whose actual object is requested to free */
  TYPE_NVLOG_ENTRY, /* nvlog: entry on nvm log */
  TYPE_BOGUS,       /* log: bogus to skip the end of a log */
  TYPE_NEW,         /* master obj allocated but not commited*/
};

enum {
  STATUS_NONE = 0,
  STATUS_TOMBSTONE_MARKED, /* chs is already tombstone-marked */
  STATUS_DETACHED,
};

enum {
  THREAD_LIVE = 0,    /* live thread */
  THREAD_LIVE_ZOMBIE, /* finished but not-yet-recalimed thread */
  THREAD_DEAD_ZOMBIE, /* zombie thread that is requested to be reclaimed */
};

enum {
  RECLAIM_TVLOG_BEST_EFFORT = 0x10,
  RECLAIM_TVLOG_CKPT = 0x11,
  RECLAIM_CKPTLOG_BEST_EFFORT = 0x20,
  RECLAIM_CKPTLOG_WRITEBACK = 0x21,
  RECLAIM_CKPTLOG_WRITEBACK_ALL = 0x22,
  RECLAIM_OPLOG_NORMAL = 0x30,
  RECLAIM_OPLOG_FORCE = 0x31,
};

#define __nvm __attribute__((nvm)) /* attribute for a pointer to nvm */
typedef signed long nvoff_t;       /* offset from the root object in nvm */

typedef struct ts_stat {
  unsigned long cnt[stat_max__];
} ts_stat_t;

/*
 * list
 */
typedef struct ts_list {
  struct ts_list *next, *prev;
} ts_list_t;

/*
 * clock
 */
typedef struct ts_sys_clks {
  volatile unsigned long __qp0;                /* current qp */
  volatile unsigned long __qp1;                /* one grace period ago */
  volatile unsigned long __qp2;                /* two grace periods ago */
  volatile unsigned long __last_ckpt;          /* last checkpoint */
  volatile unsigned long __min_ckpt_reclaimed; /* min checkpoint reclaimed */
} ts_sys_clks_t;

/*
 * log reclamation marks
 */
typedef union ts_reclaim {
  volatile unsigned int requested;
  struct {
    volatile unsigned char tvlog;
    volatile unsigned char ckptlog;
    volatile unsigned char __padding[2];
  };
} ts_reclaim_t;

/*
 * per-transaction pointer management
 */
typedef struct ts_ptr_set {
  unsigned int num_ptrs;
  unsigned int num_max_ptrs;
  void **ptrs;
} ts_ptr_set_t;

typedef struct ts_assign_ptr_entry {
  void **p_obj;
  int alloc_index;
} ts_assign_ptr_entry_t;

typedef struct ts_assign_ptr_set {
  unsigned int num_ptrs;
  unsigned int num_max_ptrs;
  ts_assign_ptr_entry_t *array;
} ts_assign_ptr_set_t;

typedef struct ts_disk_entry {
  void *src;
  size_t len;
  unsigned long commit_clk;
  uint64_t offset;
} ts_disk_entry_t;

/*
 * objects
 */
typedef struct ts_obj_hdr {
  volatile unsigned int obj_size;       /* object size for copy */
  volatile unsigned short padding_size; /* passing size in log */
  volatile unsigned char type;
  volatile unsigned char status;
  uint64_t ptr_tag;
  uint64_t canary;
  unsigned char obj[0]; /* start address of a real object */
} ____ptr_aligned ts_obj_hdr_t;

typedef struct ts_act_vhdr {
  /* header in volatile memory */
  volatile void *p_copy;
  volatile void *p_lock;
  volatile void __nvm *np_org_act; /* the original actual object */
  volatile void __nvm *np_cur_act; /* the original or the newer in log */
  uint64_t ptr_tag;
  volatile unsigned long tombstone_clk; /* when tombstone-marked in a ckptlog */
} ____cacheline_aligned ts_act_vhdr_t;

typedef struct ts_act_nvhdr {
  /* header in non-volatile memory */
  volatile uint64_t canary;
  volatile uint32_t checksum;
  volatile uint32_t vptr_checksum;
  volatile ts_act_vhdr_t *p_act_vhdr;
  volatile unsigned long gen_id;
  volatile int index;
} ____ptr_aligned ts_act_nvhdr_t;

typedef struct ts_wrt_set ts_wrt_set_t;

typedef struct ts_cpy_hdr {
  uint64_t canary;
  volatile ts_wrt_set_t *p_ws;
  /* wrt_clk: when an object is committed */
  volatile unsigned long __wrt_clk;
  /* write clock of a next node (i.e., older version) */
  volatile unsigned long wrt_clk_next;
  /* write clock of a previous node (i.e., newer version) */
  volatile unsigned long wrt_clk_prev;
  volatile void *p_copy;
  volatile ts_act_vhdr_t *p_act_vhdr;
} ____ptr_aligned ts_cpy_hdr_t;

typedef struct ts_act_hdr_struct {
  ts_act_nvhdr_t act_nvhdr;
  ts_obj_hdr_t obj_hdr;
} ts_act_hdr_struct_t;
/* removed the packed attribute to supress the compiler warning*/
//__packed ts_act_hdr_struct_t;

typedef struct ts_cpy_hdr_struct {
  ts_cpy_hdr_t cpy_hdr;
  ts_obj_hdr_t obj_hdr;
} ts_cpy_hdr_struct_t;
/* removed the packed attribute to supress the compiler warning*/
//__packed ts_cpy_hdr_struct_t;

typedef struct ts_thread_struct ts_thread_struct_t;

/*
 * transient version log
 */
typedef struct ts_wrt_set {
  volatile unsigned long wrt_clk;
  volatile unsigned long pending_wrt_clk;
  volatile unsigned int num_objs;
  unsigned long start_tail_cnt;
  ts_thread_struct_t *thread;
} ____ptr_aligned ts_wrt_set_t;

typedef struct ts_wrt_set_struct {
  ts_cpy_hdr_struct_t chs;
  ts_wrt_set_t wrt_set;
} ts_wrt_set_struct_t;
/* removed the packed attribute to supress the compiler warning*/
//__packed ts_wrt_set_struct_t;

typedef struct ts_tvlog {
  ts_sys_clks_t *clks;                  /* clks in ts_thread_struct_t */
  volatile unsigned char *need_reclaim; /* reclaim in ts_thread_struct_t */
  volatile unsigned int reclaim_lock;
  volatile unsigned long head_cnt;
  volatile unsigned long tail_cnt;
  volatile unsigned long prev_head_cnt;
  volatile unsigned long prev_tail_cnt;
  ts_wrt_set_t *cur_wrt_set;

  volatile unsigned char *buffer;
} ts_tvlog_t;

/*
 * non-volatile memory log
 */

enum {
  TYPE_NVLOG,   /* nvlog: a specific-type is not decided yet */
  TYPE_OPLOG,   /* oplog */
  TYPE_CKPTLOG, /* ckptlog */
};

enum {
  STATUS_NVLOG_NORMAL,   /* for normal thread execution */
  STATUS_NVLOG_RECOVERY, /* for recovery */
};

typedef struct ts_nvlog_entry_hdr {
  /* nvlog entry on NVM */
  uint32_t checksum;
  volatile unsigned long wrt_clk;
  volatile unsigned int size;
  volatile unsigned short type; /* {TYPE_NVLOG_ENTRY | TYPE_BOGUS} */
  unsigned char obj[0];         /* start address of an entry */
} __nvm ____ptr_aligned ts_nvlog_entry_hdr_t;

typedef struct ts_nvlog_store {
  /* nvlog on NVM */
  volatile unsigned long head_cnt;
  volatile unsigned long tail_cnt;

  volatile unsigned char *_buffer; /* allocated ptr */
  volatile unsigned char *buffer;  /* cache aligned ptr */
  unsigned long log_size;          /* size should be power of 2 */
  unsigned long mask;
  unsigned short type;
  unsigned short status;
  struct ts_nvlog_store *next;
} __nvm ts_nvlog_store_t;

typedef struct ts_nvlog {
  /* control structure of nvlog on DRAM */
  volatile unsigned long head_cnt;
  volatile unsigned long tail_cnt;
  volatile unsigned long prev_head_cnt;

  volatile unsigned int reclaim_lock;
  volatile unsigned char *need_reclaim; /* reclaim in ts_thread_struct_t */

  ts_sys_clks_t *clks; /* clks in ts_thread_struct_t */
  ts_nvlog_store_t *nvlog_store;
  volatile unsigned char *buffer;
  ts_ptr_set_t *free_set;
  ts_disk_entry_t *tx_replica_set;
  int *rs_head;
  int *rs_tail;
  unsigned long log_size; /* nvlog size */
  unsigned long mask;
  unsigned short type;
  unsigned short status;
  ts_thread_struct_t *thread;
} ts_nvlog_t;

/*
 * non-volitile memory pool root object
 */
#define NVPOOL_MAGIC 0x6E6F7453656D6954ul /* TimeSton */

typedef struct ts_nvm_root_obj {
  unsigned long magic;
  unsigned long gen_id;
  ts_nvlog_store_t *next;
  unsigned long last_ckpt_clk;
} ts_nvm_root_obj_t;

/*
 * operational log
 */
typedef ts_nvlog_t ts_oplog_t;

typedef struct ts_op_entry_hdr {
  volatile unsigned long local_clk;
  unsigned long op_type;
  unsigned char opd[0];
} __nvm ____ptr_aligned ts_op_entry_hdr_t;

typedef struct ts_op_entry {
  ts_nvlog_entry_hdr_t nvlog_hdr;
  ts_op_entry_hdr_t oplog_hdr;
} __nvm __packed ts_op_entry_t;

/*
 * checkpoint log
 */
typedef ts_nvlog_t ts_ckptlog_t;

typedef struct ts_ckpt_entry_hdr {
  volatile unsigned long ckpt_s_clk; /* checkpoint start timestamp */
  volatile void __nvm *np_org_act;   /* the original actual object */
  volatile char tombstone;           /* the original master should be freed */
} __nvm ____ptr_aligned ts_ckpt_entry_hdr_t;

typedef struct ts_ckpt_entry {
  ts_nvlog_entry_hdr_t nvlog_hdr;
  ts_ckpt_entry_hdr_t ckptlog_hdr;
  ts_obj_hdr_t obj_hdr;
} __nvm ts_ckpt_entry_t;
/* removed the packed attribute to supress the compiler warning*/
//__nvm __packed ts_ckpt_entry_t;

/*
 * qp
 */
typedef struct ts_qp_info {
  unsigned int need_wait;
  unsigned int run_cnt;
} ts_qp_info_t;

/*
 * thread
 */
#define TS_MAX_OPERAND_SIZE (256 - sizeof(ts_op_entry_hdr_t))

typedef struct ts_op_info {
  unsigned int curr;
  union {
    ts_op_entry_hdr_t op_entry;
    unsigned char __reserved[TS_MAX_OPERAND_SIZE + sizeof(ts_op_entry_hdr_t)];
    /* TODO: need to be expanded */
  };
} ts_op_info_t;

typedef struct ts_isolation_info {
  int level;
#ifdef TS_ENABLE_SERIALIZABILITY_LINEARIZABILITY
  int stale_read_occured;
  ts_ptr_set_t read_set;
#endif
} ts_isolation_info_t;

typedef struct ts_thread_struct {
  long __padding_0[TS_DEFAULT_PADDING];

  unsigned int tid;
  unsigned int socket_id;
  int in_recovery_mode;
  int is_write_detected;
  ts_isolation_info_t isolation;
  ts_ptr_set_t tx_alloc_set;
  /* ----- cacheline ----- */

  volatile unsigned int run_cnt;
  volatile int live_status;
  volatile unsigned long local_clk;
  ts_sys_clks_t clks; /* per-thread replication of
                       * the clks in ts_qp_thread_t */
  /* ----- cacheline ----- */

  ts_ptr_set_t tx_free_set;
  ts_ptr_set_t ckpt_free_set;
#ifdef TS_ENABLE_STATS
  ts_stat_t stat;
#endif
  ts_op_info_t op_info;
  ts_ptr_set_t tx_nv_alloc_set;
  /* ----- cacheline ----- */

  ts_assign_ptr_set_t tx_assign_set;
#ifdef TS_ENABLE_MOBJ_REPLICATION
  int rs_head;
  int rs_tail;
  ts_disk_entry_t tx_replica_set[MAX_SET_SIZE];
#endif
  ts_qp_info_t qp_info;
  ts_reclaim_t reclaim;
  ts_tvlog_t tvlog;
  ts_oplog_t oplog;
  ts_oplog_t oplog_replica;
  ts_ckptlog_t ckptlog;
  ts_ckptlog_t ckptlog_replica;
  long __padding_2[TS_DEFAULT_PADDING];

  ts_list_t list;
} ts_thread_struct_t;

typedef struct ts_thread_list {
  pthread_spinlock_t lock;

  long __padding_0[TS_DEFAULT_PADDING];

  volatile int thread_wait;
  unsigned int cur_tid;
  unsigned int num;
  ts_list_t list;
} ts_thread_list_t;

typedef struct io_work_data_struct {
  struct io_uring *ring;
  int fd[TN_FILES];
  int w_id;
  unsigned int *n_disk_entries;
  unsigned int n_skip;
  unsigned int n_req_comp;
  unsigned int n_sync;
  unsigned int *n_file_writes;
  bool flush_fd[TN_FILES];
  unsigned long qp_clk;
  ts_thread_struct_t **thread;
} io_work;

typedef struct ts_qp_thread {
  ts_sys_clks_t clks; /* the global system-wide clocks
                       * for reclamation. */

  pthread_t thread;
  intptr_t completion;
  pthread_mutex_t cond_mutex;
  pthread_cond_t cond;

  volatile int stop_requested;
  volatile bool wait_for_drain;
  ts_reclaim_t reclaim;

#ifdef TS_ENABLE_MOBJ_REPLICATION
  struct io_uring ring[N_IO_URING_INST_MAX];
  unsigned int n_disk_entries[N_IO_URING_INST_MAX];
  unsigned int n_disk_writes;
  unsigned int n_ring_entries[N_IO_URING_INST_MAX];
  unsigned int n_skip;
  unsigned int n_file_writes[TN_FILES];
  int fd[TN_FILES];
  bool flush_fd[TN_FILES];
  bool need_th_data_init;
  io_work *work_data;
  pthread_t *workers;
#endif

#ifdef TS_ENABLE_STATS
  ts_stat_t stat;
#endif
} ts_qp_thread_t;

/*
 * Recovery
 */
enum { OPLOG_REPLAY_TYPE_EXEC, OPLOG_REPLAY_TYPE_COMMIT };

typedef struct ts_op_context {
  ts_thread_struct_t *thread;
  ts_op_entry_t *op_entry;
} ts_op_context_t;

typedef struct ts_replay_entry {
  unsigned long time_stamp;
  int type;
  ts_op_context_t *context;
} ts_replay_entry_t;

typedef struct ts_recovery {
  ts_nvm_root_obj_t *root;
  ts_op_exec_fn_t op_exec;
} ts_recovery_t;

#ifdef __cplusplus
}
#endif
#endif /* _TIMESTONE_I_H */
