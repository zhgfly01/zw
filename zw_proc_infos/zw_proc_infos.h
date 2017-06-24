#ifndef _ZW_PROC_INFOS_H
#define _ZW_PROC_INFOS_H

#include "../comn/zw_comn.h"

typedef struct _WIN32PROC_INFO {
	char exe_bit;
	ULONG pid;
	ULONG ppid;
	std::string exe_name;
	std::string exe_path;
	std::string cmdline;
	std::string cwd;
	std::string user;
	std::string pgroup;
	std::string stime;
	SET_STR modules;
}WIN32PROC_INFO, *PWIN32PROC_INFO;

typedef std::map<ULONG, PWIN32PROC_INFO> MAP_PSS;

BOOL InitProcEnvVars();
BOOL GetProcInfoBySnapshot(MAP_PSS &pss);

BOOL Is64BitProcByHandle(HANDLE hProc);
BOOL Is64BitProcByPid(DWORD dwPid);

#endif
