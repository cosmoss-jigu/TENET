#ifndef _DISK_H
#define _DISK_H

#include <liburing.h>
#include "timestone_i.h"

#define DISK_FILE_PATH_1000 "/mnt/sd0/ts-replica-1000"
#define DISK_FILE_PATH_1001 "/mnt/sd0/ts-replica-1001"
#define DISK_FILE_PATH_1010 "/mnt/sd0/ts-replica-1010"
#define DISK_FILE_PATH_1011 "/mnt/sd0/ts-replica-1011"
#define DISK_FILE_PATH_1100 "/mnt/sd0/ts-replica-1100"
#define DISK_FILE_PATH_1101 "/mnt/sd0/ts-replica-1101"
#define DISK_FILE_PATH_1110 "/mnt/sd0/ts-replica-1110"
#define DISK_FILE_PATH_1111 "/mnt/sd0/ts-replica-1111"

#define DISK_FILE_PATH_1 "/mnt/sd0/"
#define DISK_FILE_PATH_2 "/mnt/sd1/"
#define DISK_FILE_SIZE 32ul * 1024ul * 1024ul * 1024ul

#ifdef __cplusplus
extern "C" {
#endif

int init_disk_files();
int setup_io_uring(struct io_uring *ring, int num_inst);
void replicate_to_disk(ts_thread_struct_t *self);
void sync_writes(int *fd, size_t size);
void get_disk_fds(int *fd);
void close_io_uring_instances(struct io_uring *ring);
void close_disk_files();

#ifdef __cplusplus
}
#endif
#endif
