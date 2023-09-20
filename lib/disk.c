#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "disk.h"
#include "debug.h"

static int g_n_io_uring_inst;
int *g_fd[N_SOCKET];
int __fd[N_SOCKET * _N_DISK_FILES];

void init_io_uring_queue(struct io_uring *ring, struct io_uring_params *params)
{
	int ret;

	ret = io_uring_queue_init_params(N_IO_URING_ENTRIES, ring, params);
	if (ret) {
		fprintf(stderr, "IO_URING setup failed: %s\n", strerror(-ret));
		exit(0);
	}
}

void register_files(struct io_uring *ring)
{
	int ret;
	int f_cnt = _N_DISK_FILES * N_SOCKET;

	/* all rings can write to any nvm file*/
	ret = io_uring_register_files(ring, __fd, f_cnt);
	if (ret) {
		fprintf(stderr, "IO_URING file register failed: %s\n",
			strerror(-ret));
		exit(0);
	}
}

int setup_io_uring(struct io_uring *ring, int n_io_inst)
{
	struct io_uring_params params;
	int i;

	/*
	 * TODO: pass the idle cpuset from the application side 
	 * to the io_uring kernel thread*
	 */
	memset(&params, 0, sizeof(params));
	/* setup the io_uring instance in the polling mode*/
	params.flags |= IORING_SETUP_SQPOLL;
	params.sq_thread_idle = IO_URING_IDLE;
	init_disk_files();
	for (i = 0; i < n_io_inst; ++i) {
		init_io_uring_queue(&ring[i], &params);
		register_files(&ring[i]);

		ts_trace(TS_QP, "ring_fd[%d]= %d ring_capacity: %d\n ", i,
			 ring[i].ring_fd, params.sq_entries);
	}
	g_n_io_uring_inst = n_io_inst;
	return 0;
}

static void setup_disk_files(int start, int end, int p_id)
{
	char path[64];
	char buff[32];

	for (int i = start; i < end; ++i) {
		memset(path, 0, strlen(path));
		memset(buff, 0, strlen(buff));
		sprintf(buff, "tss-replica-%d", i);

		if (p_id == 0)
			strcat(path, DISK_FILE_PATH_1);
		else
			strcat(path, DISK_FILE_PATH_2);

		strcat(path, buff);
		ts_trace(TS_DEBUG, "path= %s\n", path);
		__fd[i] = open(path, O_RDWR | O_TRUNC | O_CREAT, 0644);
		if (__fd[i] == -1) {
			ts_trace(TS_INFO, "Error creating file \n");
			exit(1);
		}
		//fallocate(__fd[i], FALLOC_FL_KEEP_SIZE, 0, DISK_FILE_SIZE);
		ftruncate(__fd[i], DISK_FILE_SIZE);
		ts_trace(TS_DEBUG, "__fd[%d]= %d \n", i, __fd[i]);
	}
	return;
}

int init_disk_files()
{
	int start, end;

	for (int i = 0; i < N_SOCKET; ++i) {
		start = i * _N_DISK_FILES;
		end = start + _N_DISK_FILES;
		setup_disk_files(start, end, i);
	}
	return 0;
}

void get_disk_fds(int *fd)
{
	int cnt = N_SOCKET * _N_DISK_FILES;

	for (int i = 0; i < cnt; ++i) {
		fd[i] = __fd[i];
	}
	return;
}

void close_disk_files()
{
	int i, ret;
	int cnt = N_SOCKET * _N_DISK_FILES;

	for (i = 0; i < cnt; ++i) {
		ret = close(__fd[i]);
		if (ret < 0)
			perror("Failed to close the Disk Files\n");
	}
}

void close_io_uring_instances(struct io_uring *ring)
{
	int i;

	for (i = 0; i < g_n_io_uring_inst; ++i) {
		io_uring_queue_exit(&ring[i]);
	}
	close_disk_files();
}
