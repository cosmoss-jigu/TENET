#ifndef _RECOVERY_H
#define _RECOVERY_H

#include "nvlog.h"
#include "timestone_i.h"
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

int ckptlog_recovery(ts_recovery_t *);
int oplog_recovery(ts_recovery_t *);
int perform_recovery(ts_recovery_t *);

#ifdef __cplusplus
}
#endif
#endif
