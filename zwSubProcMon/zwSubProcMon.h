#ifndef _ZW_SUBPROCMON_H
#define _ZW_SUBPROCMON_H

#include "../comn/zw_comn.h"

#define ZW_CPU_RATE_MAX_LOW		50
#define ZW_CPU_RATE_MAX_HIGH	100
#define ZW_MEM_MAX_LOW			(1024 * 1024 * 30)
#define ZW_MEM_MAX_HIGH			(1024 * 1024 * 60)

typedef struct _MON_PROC_PARAM {
	HANDLE hProcess;
	HANDLE hThread;
}MON_PROC_PARAM, *PMON_PROC_PARAM;

int SubProcMon(const char *pcszApp, char *pszCmdline);

#endif
