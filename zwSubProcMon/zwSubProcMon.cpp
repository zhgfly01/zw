#include "zwSubProcMon.h"
#include <stdio.h>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")

/*
进程的CPU占用率 = 进程消耗的CPU时间 / 刷新周期
进程消耗的CPU时间 = 进程消耗的内核态时间 + 进程消耗的用户态时间，即 costTime = kernelTime + UserTime
http://stackoverflow.com/questions/63166/how-to-determine-cpu-and-memory-consumption-from-inside-a-process
*/
static DWORD g_dwProcessorCoreNum = 0;					// 处理器核心数
static LARGE_INTEGER g_slgProcessTimeOld = { 0 };		// 保存进程上一次的时间占用


static int GetProcessCpuPercent(const HANDLE hProcess, const DWORD dwElepsedTime)
{
	int nProcCpuPercent = 0;
	BOOL bRetCode = FALSE;

	FILETIME CreateTime, ExitTime, KernelTime, UserTime;
	LARGE_INTEGER lgKernelTime;
	LARGE_INTEGER lgUserTime;
	LARGE_INTEGER lgCurTime;

	bRetCode = GetProcessTimes(hProcess, &CreateTime, &ExitTime, &KernelTime, &UserTime);
	if (bRetCode) {
		lgKernelTime.HighPart = KernelTime.dwHighDateTime;
		lgKernelTime.LowPart = KernelTime.dwLowDateTime;

		lgUserTime.HighPart = UserTime.dwHighDateTime;
		lgUserTime.LowPart = UserTime.dwLowDateTime;

		lgCurTime.QuadPart = (lgKernelTime.QuadPart + lgUserTime.QuadPart) / 10000;
		nProcCpuPercent = (int)((lgCurTime.QuadPart - g_slgProcessTimeOld.QuadPart) * 100 / dwElepsedTime);
		g_slgProcessTimeOld = lgCurTime;

		nProcCpuPercent = nProcCpuPercent / g_dwProcessorCoreNum;
	}
	else
		nProcCpuPercent = -1;

	return nProcCpuPercent;
}

static DWORD GetProcessMemUsage(const HANDLE hProcess)
{
	PROCESS_MEMORY_COUNTERS_EX pmc = { 0 };
	pmc.cb = sizeof(pmc);
	if (GetProcessMemoryInfo(hProcess, (PPROCESS_MEMORY_COUNTERS)&pmc, sizeof(pmc)))
		return pmc.PrivateUsage;
	else
		return -1;
}

unsigned __stdcall MonWorkThread(void *pvParam)
{
	PMON_PROC_PARAM pmpp = NULL;
	DWORD dwRetVal = 0;
	DWORD dwOldTickCount = 0;
	DWORD dwCurrentTickCount = 0;
	DWORD dwElapsedTime = 0;
	BOOL bFlag = FALSE;
	int nProcessCpuPercent = 0;
	DWORD dwMemUsage = 0;

	pmpp = (PMON_PROC_PARAM)pvParam;
	ResumeThread(pmpp->hThread);
	do {
		dwRetVal = WaitForSingleObject(pmpp->hProcess, 1000);
		if (WAIT_OBJECT_0 == dwRetVal || WAIT_FAILED == dwRetVal)
			break;

		dwCurrentTickCount = GetTickCount();
		dwElapsedTime = dwCurrentTickCount - dwOldTickCount;
		dwOldTickCount = dwCurrentTickCount;
		nProcessCpuPercent = GetProcessCpuPercent(pmpp->hProcess, dwElapsedTime);
		dwMemUsage = GetProcessMemUsage(pmpp->hProcess);
		if (!bFlag) {
			bFlag = TRUE;
			continue;
		}
		if (nProcessCpuPercent == -1 ||
			(g_dwProcessorCoreNum <= 4 && nProcessCpuPercent >= ZW_CPU_RATE_MAX_LOW) ||
			(g_dwProcessorCoreNum > 4 && nProcessCpuPercent >= ZW_CPU_RATE_MAX_HIGH))
		{
			fprintf(stderr, "script cpu is out of limits\n");
			if (!TerminateProcess(pmpp->hProcess, -1)) continue; else break;
		}
		if (dwMemUsage == -1 ||
			(g_dwProcessorCoreNum <= 4 && dwMemUsage >= ZW_MEM_MAX_LOW) ||
			(g_dwProcessorCoreNum > 4 && dwMemUsage >= ZW_MEM_MAX_HIGH))
		{
			fprintf(stderr, "script's mem is out of limits\n");
			if (!TerminateProcess(pmpp->hProcess, -1)) continue; else break;
		}
	} while (1);

	return 0;
}

int SubProcMon(const char *pcszApp, char *pszCmdline)
{
	int nRetVal = 0;
	SYSTEM_INFO sysInfo = { 0 };
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	MON_PROC_PARAM mpp = { 0 };
	HANDLE hMon = NULL;
	DWORD dwSubExitCode = 0;

	GetNativeSystemInfo(&sysInfo);
	g_dwProcessorCoreNum = sysInfo.dwNumberOfProcessors;
	if (g_dwProcessorCoreNum <= 0) {
		fprintf(stderr, "get cpu info error\n");
		return ZW_ERROR;
	}

	si.cb = sizeof(STARTUPINFOA);
//	si.dwFlags = STARTF_USESHOWWINDOW;
//	si.wShowWindow = SW_HIDE;
	if (!CreateProcessA(pcszApp, pszCmdline, NULL, NULL, FALSE, 
		CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		fprintf(stderr, "create new process for script error\n");
		return ZW_ERROR;
	}

	/* 写PID到文件 */

	mpp.hProcess = pi.hProcess;
	mpp.hThread = pi.hThread;
	hMon = PFNBTEX(NULL, 0, MonWorkThread, &mpp, 0, NULL);

	if (WaitForSingleObject(hMon, 1000 * 60 * 5) == WAIT_TIMEOUT) {
		nRetVal = ZW_ERROR;
		goto Exit1;
	}
	CloseHandle(hMon);

	if (!GetExitCodeProcess(pi.hProcess, &dwSubExitCode)) {
		nRetVal = ZW_ERROR;
		goto Exit0;
	}
	if (dwSubExitCode != 0) {
		nRetVal = ZW_ERROR;
		goto Exit1;
	}
	else {
		nRetVal = ZW_SUCCESS;
		goto Exit0;
	}

Exit1:
	TerminateProcess(pi.hProcess, -1);
Exit0:
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return nRetVal;
}