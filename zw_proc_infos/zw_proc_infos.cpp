#include "zw_proc_infos.h"
#include <TlHelp32.h>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")
#include "../comn/zw_cs.h"

#ifndef _WINTERNL_
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessWow64Information = 26
} PROCESSINFOCLASS;
#endif

/* ------------------------------------------------ */
typedef struct _PROCESS_BASIC_INFORMATION_T {
	PVOID Reserved1;
	PVOID PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
}PROCESS_BASIC_INFORMATION_T;

typedef struct _UNICODE_STRING32{
	USHORT Length;
	USHORT MaxLength;
	DWORD Buffer;
}UNICODE_STRING32;
typedef struct _UNICODE_STRING64{
	USHORT Length;
	USHORT MaxLength;
	PVOID64 Buffer;
}UNICODE_STRING64;

typedef struct _PROCESS_BASIC_INFORMATION64{
	PVOID Reserved1[2];
	PVOID64 PebBaseAddress;
	PVOID Reserved2[4];
	PVOID UniqueProcessId[2];
	PVOID Reserved3[2];
}PROCESS_BASIC_INFORMATION64;

typedef struct _RTL_USER_PROCESS_PARAMETERS32{
	BYTE Reserved1[16];
	DWORD Reserved2[5];
	UNICODE_STRING32 CurrentDirectory;
	DWORD CurrentDirectoryHandle;
	UNICODE_STRING32 DllPath;
	UNICODE_STRING32 ImagePathName;
	UNICODE_STRING32 CommandLine;
	DWORD env;
}RTL_USER_PROCESS_PARAMETERS32;
typedef struct _RTL_USER_PROCESS_PARAMETERS64{
	BYTE Reserved1[16];
	PVOID64 Reserved2[5];
	UNICODE_STRING64 CurrentDirectory;
	PVOID64 CurrentDirectoryHandle;
	UNICODE_STRING64 DllPath;
	UNICODE_STRING64 ImagePathName;
	UNICODE_STRING64 CommandLine;
	PVOID64 env;
}RTL_USER_PROCESS_PARAMETERS64;

typedef struct _PEB32{
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	DWORD Reserved3[2];
	DWORD Ldr;
	DWORD ProcessParameters;
	/* More fields ...  */
}PEB32;
typedef struct _PEB64{
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[21];
	PVOID64 Ldr;
	PVOID64 ProcessParameters;
	/* More fields ...  */
}PEB64;

typedef struct _PEB_LDR_DATA64 {
	ULONG Length;
	UCHAR Initialized;
	PVOID64 SsHandle;
	LIST_ENTRY64 InLoadOrderModuleList;
	LIST_ENTRY64 InMemoryOrderModuleList;
}PEB_LDR_DATA64;
typedef struct _PEB_LDR_DATA32 {
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
}PEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY64 {
	LIST_ENTRY64 InLoadOrderLinks;
	LIST_ENTRY64 InMemoryOrderLinks;
	LIST_ENTRY64 InInitializationOrderLinks;
	PVOID64 DllBase;
	PVOID64 EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING64 FullDllName;
	UNICODE_STRING64 BaseDllName;
}LDR_DATA_TABLE_ENTRY64;
typedef struct _LDR_DATA_TABLE_ENTRY32 {
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
}LDR_DATA_TABLE_ENTRY32;

#ifdef _WIN64
#define UNICODE_STRING_T UNICODE_STRING64
#define PEB_T PEB64
#define PEB_LDR_DATA_T PEB_LDR_DATA64
#define LDR_DATA_TABLE_ENTRY_T LDR_DATA_TABLE_ENTRY64
#define RTL_USER_PROCESS_PARAMETERS_T RTL_USER_PROCESS_PARAMETERS64
#define LIST_ENTRY_T LIST_ENTRY64
#define PLIST_ENTRY_T PLIST_ENTRY64
#else
#define UNICODE_STRING_T UNICODE_STRING32
#define PEB_T PEB32
#define PEB_LDR_DATA_T PEB_LDR_DATA32
#define LDR_DATA_TABLE_ENTRY_T LDR_DATA_TABLE_ENTRY32
#define RTL_USER_PROCESS_PARAMETERS_T RTL_USER_PROCESS_PARAMETERS32
#define LIST_ENTRY_T LIST_ENTRY32
#define PLIST_ENTRY_T PLIST_ENTRY32
#endif
/* ------------------------------------------------ */

typedef BOOL (WINAPI *PFN_ISWOW64PROCESS)(HANDLE, PBOOL);
typedef NTSTATUS (WINAPI *PFN_NTQUERYINFORMATIONPROCESS)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);
#ifndef _WIN64
typedef NTSTATUS(WINAPI *PFN_NTWOW64QUERYINFORMATIONPROCESS64)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation64,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);
typedef NTSTATUS(WINAPI *PFN_NTWOW64READVIRTUALMEMORY64)(
	HANDLE ProcessHandle,
	PVOID64 BaseAddress,
	PVOID Buffer,
	ULONG64 BufferSize,
	PULONG64 NumberOfBytesRead
	);
PFN_NTQUERYINFORMATIONPROCESS pfnNtWow64QueryInformationProcess64 = 0;
PFN_NTWOW64READVIRTUALMEMORY64 pfnNtWow64ReadVirtualMemory64 = 0;
#endif

PFN_ISWOW64PROCESS pfnIsWow64Process = 0;
PFN_NTQUERYINFORMATIONPROCESS pfnNtQueryInformationProcess = 0;

BOOL g_b64BitOs = FALSE;
BOOL g_bWowSelf = FALSE;

static BOOL GetUnDocFunc()
{
	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hKernel32 || !hNtdll) return FALSE;

	pfnIsWow64Process = (PFN_ISWOW64PROCESS)GetProcAddress(hKernel32, "IsWow64Process");
	pfnNtQueryInformationProcess = (PFN_NTQUERYINFORMATIONPROCESS)
		GetProcAddress(hNtdll, "NtQueryInformationProcess");
#ifdef _WIN64
	if (!pfnIsWow64Process ||
		!pfnNtQueryInformationProcess) {
#else
	pfnNtWow64QueryInformationProcess64 = (PFN_NTWOW64QUERYINFORMATIONPROCESS64)
		GetProcAddress(hNtdll, "NtWow64QueryInformationProcess64");
	pfnNtWow64ReadVirtualMemory64 = (PFN_NTWOW64READVIRTUALMEMORY64)
		GetProcAddress(hNtdll, "NtWow64ReadVirtualMemory64");
	if (!pfnIsWow64Process ||
		!pfnNtQueryInformationProcess ||
		!pfnNtWow64QueryInformationProcess64 ||
		!pfnNtWow64ReadVirtualMemory64) {
#endif
		return FALSE;
	}
	else {
		return TRUE;
	}
}

BOOL Is64BitProcByHandle(HANDLE hProc)
{
	if (g_b64BitOs) {
		BOOL bIsWow64 = FALSE;
		if (!hProc)
			return FALSE;
		if (pfnIsWow64Process(hProc, &bIsWow64))
			return bIsWow64 ? FALSE : TRUE;
		else
			return FALSE;
	}
	else
		return FALSE;
}
BOOL Is64BitProcByPid(DWORD dwPid)
{
	if (g_b64BitOs) {
		HANDLE hProc = 0;
		BOOL bRet = FALSE;
		hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid);
		bRet = Is64BitProcByHandle(hProc);
		CloseHandle(hProc);
		return bRet;
	}
	else
		return FALSE;
}

#ifdef _WIN64
static BOOL GetProcDetails32O64ByHandle(PWIN32PROC_INFO each_ps, HANDLE hProc)
{
	ULONG64 ullPebAddr = 0;
	ULONG ullPPAddr = 0;
	UNICODE_STRING32 usTmp = { 0 };
	WCHAR *iBuf = NULL;
	char *pszTmp = NULL;
	SIZE_T sRealRead = 0;

	if (!NT_SUCCESS(pfnNtQueryInformationProcess(hProc, ProcessWow64Information, 
		&ullPebAddr, sizeof(ullPebAddr), 0)))
		return FALSE;
	if (!ReadProcessMemory(hProc, 
		(PCHAR)ullPebAddr + FIELD_OFFSET32(PEB32, ProcessParameters),
		&ullPPAddr, sizeof(ullPPAddr), 0))
		return FALSE;
	if (!ReadProcessMemory(hProc, 
		(PCHAR)ullPPAddr + FIELD_OFFSET32(RTL_USER_PROCESS_PARAMETERS32, ImagePathName),
		&usTmp, sizeof(usTmp), 0))
		return FALSE;

	iBuf = (PWCHAR)malloc(usTmp.Length + sizeof(WCHAR));
	if (ReadProcessMemory(hProc, (PVOID)usTmp.Buffer, iBuf, usTmp.Length, &sRealRead)) {
		iBuf[sRealRead / 2] = L'\0';
		if (!ws2utf8(&pszTmp, iBuf)) {
			each_ps->exe_path = pszTmp;
			FREE_NUL(pszTmp);
		}
		else
			each_ps->exe_path = "null";
	}
	FREE_NUL(iBuf);

	if (!ReadProcessMemory(hProc, 
		(PCHAR)ullPPAddr + FIELD_OFFSET32(RTL_USER_PROCESS_PARAMETERS32, CommandLine),
		&usTmp, sizeof(usTmp), 0))
		return FALSE;
	iBuf = (PWCHAR)malloc(usTmp.Length + sizeof(WCHAR));
	if (ReadProcessMemory(hProc, (PVOID)usTmp.Buffer, iBuf, usTmp.Length, &sRealRead)) {
		iBuf[sRealRead / 2] = L'\0';
		if (!ws2utf8(&pszTmp, iBuf)) {
			each_ps->cmdline = pszTmp;
			FREE_NUL(pszTmp);
		}
		else
			each_ps->cmdline = "null";
	}
	FREE_NUL(iBuf);

	if (!ReadProcessMemory(hProc, 
		(PCHAR)ullPPAddr + FIELD_OFFSET32(RTL_USER_PROCESS_PARAMETERS32, CurrentDirectory),
		&usTmp, sizeof(usTmp), 0))
		return FALSE;
	iBuf = (PWCHAR)malloc(usTmp.Length + sizeof(WCHAR));
	if (ReadProcessMemory(hProc, (PVOID)usTmp.Buffer, iBuf, usTmp.Length, &sRealRead)) {
		iBuf[sRealRead / 2] = L'\0';
		if (!ws2utf8(&pszTmp, iBuf)) {
			each_ps->cwd = pszTmp;
			FREE_NUL(pszTmp);
		}
		else
			each_ps->cwd = "null";
	}
	FREE_NUL(iBuf);


	return TRUE;
}
#else
static BOOL GetProcDetails64O32ByHandle(PWIN32PROC_INFO each_ps, HANDLE hProc)
{
	NTSTATUS nss = -1;
	PROCESS_BASIC_INFORMATION64 pbi64 = { 0 };
	PEB64 peb64 = { 0 };
	RTL_USER_PROCESS_PARAMETERS64 upp64 = { 0 };
	WCHAR *iBuf = NULL;
	char *pszTmp = NULL;
	ULONG64 ulRealRead = 0;

	nss = pfnNtWow64QueryInformationProcess64(hProc, ProcessBasicInformation,
		(PVOID)&pbi64, sizeof(PROCESS_BASIC_INFORMATION64), 0);
	if (!NT_SUCCESS(nss)) return FALSE;
	nss = pfnNtWow64ReadVirtualMemory64(hProc, pbi64.PebBaseAddress, &peb64, sizeof(PEB64), 0);
	if (!NT_SUCCESS(nss)) return FALSE;
	nss = pfnNtWow64ReadVirtualMemory64(hProc, peb64.ProcessParameters,
		&upp64, sizeof(RTL_USER_PROCESS_PARAMETERS64), 0);
	if (!NT_SUCCESS(nss)) return FALSE;

	iBuf = (PWCHAR)malloc(upp64.CommandLine.Length + sizeof(WCHAR));
	nss = pfnNtWow64ReadVirtualMemory64(hProc, upp64.CommandLine.Buffer,
		iBuf, upp64.CommandLine.Length, &ulRealRead);
	if (NT_SUCCESS(nss)) {
		iBuf[ulRealRead / 2] = L'\0';
		if (!ws2utf8(&pszTmp, iBuf)) {
			each_ps->cmdline = pszTmp;
			FREE_NUL(pszTmp);
		}
		else
			each_ps->cmdline = "null";
	}
	FREE_NUL(iBuf);

	iBuf = (PWCHAR)malloc(upp64.ImagePathName.Length + sizeof(WCHAR));
	nss = pfnNtWow64ReadVirtualMemory64(hProc, upp64.ImagePathName.Buffer,
		iBuf, upp64.ImagePathName.Length, &ulRealRead);
	if (NT_SUCCESS(nss)) {
		iBuf[ulRealRead / 2] = L'\0';
		if (!ws2utf8(&pszTmp, iBuf)) {
			each_ps->exe_path = pszTmp;
			FREE_NUL(pszTmp);
		}
		else
			each_ps->exe_path = "null";
	}
	FREE_NUL(iBuf);

	iBuf = (PWCHAR)malloc(upp64.CurrentDirectory.Length + sizeof(WCHAR));
	nss = pfnNtWow64ReadVirtualMemory64(hProc, upp64.CurrentDirectory.Buffer,
		iBuf, upp64.CurrentDirectory.Length, &ulRealRead);
	if (NT_SUCCESS(nss)) {
		iBuf[ulRealRead / 2] = L'\0';
		if (!ws2utf8(&pszTmp, iBuf)) {
			each_ps->cwd = pszTmp;
			FREE_NUL(pszTmp);
		}
		else
			each_ps->cwd = "null";
	}
	FREE_NUL(iBuf);


	return TRUE;
}
#endif
static BOOL GetProcDetailsNormalByHandle(PWIN32PROC_INFO each_ps, HANDLE hProc, BOOL bWowSelf)
{
	PROCESS_BASIC_INFORMATION_T pbi = { 0 };
	ULONG_PTR ulpPPAddr = 0;
	UNICODE_STRING_T usTmp = { 0 };
	WCHAR *iBuf = NULL;
	char *pszTmp = NULL;
	SIZE_T sRealRead = 0;

	if (!NT_SUCCESS(pfnNtQueryInformationProcess(hProc, ProcessBasicInformation, 
		(PVOID)&pbi, sizeof(pbi), 0)))
		return FALSE;
	if (!ReadProcessMemory(hProc, 
		(PCHAR)pbi.PebBaseAddress + FIELD_OFFSET(PEB_T, ProcessParameters),
		&ulpPPAddr, sizeof(ulpPPAddr), 0))
		return FALSE;
	if (!ReadProcessMemory(hProc, 
		(PCHAR)ulpPPAddr + FIELD_OFFSET_T(RTL_USER_PROCESS_PARAMETERS_T, CommandLine),
		&usTmp, sizeof(usTmp), 0))
		return FALSE;

	iBuf = (PWCHAR)malloc(usTmp.Length + sizeof(WCHAR));
	if (ReadProcessMemory(hProc, (PVOID)usTmp.Buffer, iBuf, usTmp.Length, &sRealRead)) {
		iBuf[sRealRead / 2] = L'\0';
		if (!ws2utf8(&pszTmp, iBuf)) {
			each_ps->cmdline = pszTmp;
			FREE_NUL(pszTmp);
		}
		else
			each_ps->cmdline = "null";
	}
	FREE_NUL(iBuf);

	if (!ReadProcessMemory(hProc, 
		(PCHAR)ulpPPAddr + FIELD_OFFSET_T(RTL_USER_PROCESS_PARAMETERS_T, ImagePathName),
		&usTmp, sizeof(usTmp), 0))
		return FALSE;
	iBuf = (PWCHAR)malloc(usTmp.Length + sizeof(WCHAR));
	if (ReadProcessMemory(hProc, (PVOID)usTmp.Buffer, iBuf, usTmp.Length, &sRealRead)) {
		iBuf[sRealRead / 2] = L'\0';
		if (!ws2utf8(&pszTmp, iBuf)) {
			each_ps->exe_path = pszTmp;
			FREE_NUL(pszTmp);
		}
		else
			each_ps->exe_path = "null";
	}
	FREE_NUL(iBuf);

	if (!ReadProcessMemory(hProc, 
		(PCHAR)ulpPPAddr + FIELD_OFFSET_T(RTL_USER_PROCESS_PARAMETERS_T, CurrentDirectory),
		&usTmp, sizeof(usTmp), 0))
		return FALSE;
	iBuf = (PWCHAR)malloc(usTmp.Length + sizeof(WCHAR));
	if (ReadProcessMemory(hProc, (PVOID)usTmp.Buffer, iBuf, usTmp.Length, &sRealRead)) {
		iBuf[sRealRead / 2] = L'\0';
		if (!ws2utf8(&pszTmp, iBuf)) {
			each_ps->cwd = pszTmp;
			FREE_NUL(pszTmp);
		}
		else
			each_ps->cwd = "null";
	}
	FREE_NUL(iBuf);


	return TRUE;
}

static void GetProcTokenInfo(PWIN32PROC_INFO each_ps, HANDLE hProc)
{
	HANDLE hToken = INVALID_HANDLE_VALUE;
	DWORD dwSize = 0;
	DWORD dwResult = 0;
	PTOKEN_USER pTokenUser = NULL;
	WCHAR szName[MAX_PATH] = { 0 };
	WCHAR szDomain[MAX_PATH] = { 0 };
	SID_NAME_USE SidType;
	PTOKEN_GROUPS pGroupInfo = NULL;
	char *pszTmp = NULL;

	if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken))
		return;
	if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize))
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			goto END0;

	pTokenUser = (PTOKEN_USER)malloc(dwSize);
	if (!pTokenUser)
		goto END0;
	if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize))
		goto END;
	dwSize = MAX_PATH;
	if (!LookupAccountSidW(NULL, pTokenUser->User.Sid, szName, &dwSize, szDomain, &dwSize, &SidType)) {
		each_ps->user = "null";
		goto END;
	}
	if (!ws2utf8(&pszTmp, szDomain)) {
		each_ps->user += pszTmp;
		FREE_NUL(pszTmp);
	}
	each_ps->user += '\\';
	if (!ws2utf8(&pszTmp, szName)) {
		each_ps->user += pszTmp;
		FREE_NUL(pszTmp);
	}

	if (!GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwSize))
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			goto END;
	pGroupInfo = (PTOKEN_GROUPS)malloc(dwSize);
	if (!pGroupInfo)
		goto END;
	if (!GetTokenInformation(hToken, TokenGroups, pGroupInfo, dwSize, &dwSize))
		goto END1;
	for (DWORD i = 0; i < pGroupInfo->GroupCount; i++) {
		memset(szName, 0, MAX_PATH*sizeof(WCHAR));
		memset(szDomain, 0, MAX_PATH*sizeof(WCHAR));
		dwSize = MAX_PATH;
		if (!LookupAccountSidW(NULL, pGroupInfo->Groups[i].Sid,
			szName, &dwSize, szDomain, &dwSize, &SidType)) {
			continue;
		}
		if (!ws2utf8(&pszTmp, szDomain)) {
			each_ps->pgroup += pszTmp;
			FREE_NUL(pszTmp);
		}
		each_ps->pgroup += '\\';
		if (!ws2utf8(&pszTmp, szName)) {
			each_ps->pgroup += pszTmp;
			FREE_NUL(pszTmp);
		}
		each_ps->pgroup += ';';
	}

END1:
	if (pGroupInfo)
		free(pGroupInfo);
END:
	if (pTokenUser)
		free(pTokenUser);
END0:
	CloseHandle(hToken);
	return;
}
static void GetProcOtherInfo(PWIN32PROC_INFO each_ps, HANDLE hProc)
{
	FILETIME ProcCreateft, ProcExitft, ProcKernelft, ProcUserft;
	if (!GetProcessTimes(hProc, &ProcCreateft, &ProcExitft, &ProcKernelft, &ProcUserft))
		each_ps->stime = "null";
	else {
		FILETIME ftLocal;
		SYSTEMTIME st;
		char lftime[32] = { 0 };
		FileTimeToLocalFileTime(&ProcCreateft, &ftLocal);
		FileTimeToSystemTime(&ftLocal, &st);
		sprintf_s(lftime, "%04d-%02d-%02d %02d:%02d:%02d",
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
		each_ps->stime = lftime;
	}
}

static BOOL GetProcDetailsByPid(PWIN32PROC_INFO each_ps, DWORD dwPid)
{
	HANDLE hProc = 0;
	hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPid);
	if (!hProc)
		return FALSE;

	BOOL bRet = FALSE;
	each_ps->exe_bit = Is64BitProcByHandle(hProc);
	GetProcTokenInfo(each_ps, hProc);
	GetProcOtherInfo(each_ps, hProc);
#ifdef _WIN64
	if (each_ps->exe_bit)
		bRet = GetProcDetailsNormalByHandle(each_ps, hProc, FALSE);
	else
		bRet = GetProcDetails32O64ByHandle(each_ps, hProc);
#else
	if (g_b64BitOs)
		if (each_ps->exe_bit)
			bRet = GetProcDetails64O32ByHandle(each_ps, hProc);
		else
			bRet = GetProcDetailsNormalByHandle(each_ps, hProc, g_bWowSelf);
	else
		bRet = GetProcDetailsNormalByHandle(each_ps, hProc, FALSE);
#endif
	CloseHandle(hProc);
	return bRet;
}

BOOL GetProcInfoBySnapshot(MAP_PSS &pss)
{
	HANDLE hProcSnapshot = 0;
	PROCESSENTRY32 pe32 = { 0 };
	DWORD dwSelfPID = 0;

	hProcSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcSnapshot == INVALID_HANDLE_VALUE)
		return FALSE;
	dwSelfPID = GetCurrentProcessId();

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hProcSnapshot, &pe32)) {
		CloseHandle(hProcSnapshot);
		return FALSE;
	}
	do {
		if (!pe32.th32ParentProcessID || dwSelfPID == pe32.th32ProcessID)
			continue;

		PWIN32PROC_INFO each_ps = new WIN32PROC_INFO();
		each_ps->exe_bit = 0;
		each_ps->pid = pe32.th32ProcessID;
		each_ps->ppid = pe32.th32ParentProcessID;
#if defined(UNICODE) || defined(_UNICODE)
		char *pszTmp = NULL;
		if (!ws2utf8(&pszTmp, pe32.szExeFile)) {
			each_ps->exe_name = pszTmp;
			FREE_NUL(pszTmp);
		}
		else
			each_ps->exe_name = "null";
#else
		char *pszTmp = NULL;
		if (!s2utf8(&pszTmp, pe32.szExeFile)) {
			each_ps->exe_name = pszTmp;
			FREE_NUL(pszTmp);
		}
		else
			each_ps->exe_name = pe32.szExeFile;
#endif
		if (GetProcDetailsByPid(each_ps, pe32.th32ProcessID))
			pss[pe32.th32ProcessID] = each_ps;
		else
			delete each_ps;
		//Sleep(100);
	} while (Process32Next(hProcSnapshot, &pe32));
	CloseHandle(hProcSnapshot);
	return TRUE;
}

BOOL InitProcEnvVars()
{
	BOOL bIsWow64 = FALSE;

	if (!DebugPrivilege(TRUE))
		return FALSE;
	if (!GetUnDocFunc())
		return FALSE;

	g_b64BitOs = Is64BitOS();
	if (pfnIsWow64Process(GetCurrentProcess(), &bIsWow64))
		g_bWowSelf = bIsWow64;
	else
		g_bWowSelf = FALSE;
	return TRUE;
}