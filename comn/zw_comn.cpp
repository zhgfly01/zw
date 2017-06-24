#include "zw_comn.h"
#include <stdio.h>
#include <io.h>

const char *pcszAppPath = NULL;
char szAppPath[MAX_PATH] = { 0 };

BOOL GetAppPath(void)
{
	char *p = NULL;
	if (!GetModuleFileNameA(NULL, szAppPath, MAX_PATH))
		return FALSE;
	p = strrchr(szAppPath, '\\');
	*(p + 1) = '\0';
	pcszAppPath = (const char *)(szAppPath);
	return TRUE;
}

/*
测试：
void tdCallBack(const char *pcszFilePath)
{
	printf("--%s\n", pcszFilePath);
}
int main()
{
	WalkDir("D:\\WorkSpace", 0, "*.*", tdCallBack);
	return 0;
}
*/
void WalkDir(
	const char *pcszDirPath, 
	int bSub, 
	const char *pcszWildcard, 
	PFN_TDCALLBACK pfnCallBack
	)
{
	char szFullPath[_MAX_PATH] = { 0 };
	char szCurFind[_MAX_PATH] = { 0 };
	int nLen = 0;
	struct _finddata_t tFileInfo = { 0 };
	intptr_t hFile = 0;

	if (_fullpath(szFullPath, pcszDirPath, _MAX_PATH) == NULL)
		return;
	if (_access(szFullPath, 0) == -1)
		return;

	nLen = (int)strlen(szFullPath);
	if (szFullPath[nLen - 1] != '\\')
		szFullPath[nLen] = '\\';
	//sprintf(szCurFind, "%s%s", szFullPath, pcszWildcard);
	sprintf_s(szCurFind, "%s%s", szFullPath, pcszWildcard);

	if ((hFile = _findfirst(szCurFind, &tFileInfo)) == -1L)
		return;
	do {
		//判断是否有子目录
		if (tFileInfo.attrib & _A_SUBDIR) {
			if ((strcmp(tFileInfo.name, ".") == 0) || (strcmp(tFileInfo.name, "..") == 0))
				continue;
			if (bSub) {
				memset(szCurFind, 0, _MAX_PATH);
				//sprintf(szCurFind, "%s%s", szFullPath, tFileInfo.name);
				sprintf_s(szCurFind, "%s%s", szFullPath, tFileInfo.name);
				WalkDir(szCurFind, bSub, pcszWildcard, pfnCallBack);
			}
		}
		else {
			memset(szCurFind, 0, _MAX_PATH);
			//sprintf(szCurFind, "%s%s", szFullPath, tFileInfo.name);
			sprintf_s(szCurFind, "%s%s", szFullPath, tFileInfo.name);
			pfnCallBack(szCurFind);
		}
	} while (_findnext(hFile, &tFileInfo) == 0);
	_findclose(hFile);
}

BOOL DebugPrivilege(BOOL bEnable)
{
	BOOL              bRet = TRUE;
	HANDLE            hToken = NULL;
	TOKEN_PRIVILEGES  TokenPrivileges = { 0 };

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
		return FALSE;
	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &TokenPrivileges.Privileges[0].Luid);
	AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, 
		sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (GetLastError() != ERROR_SUCCESS)
		bRet = FALSE;

	CloseHandle(hToken);
	return bRet;
}

BOOL Is64BitOS(void)
{
	SYSTEM_INFO stInfo = { 0 };
	GetNativeSystemInfo(&stInfo);
	if (stInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
		stInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
		return TRUE;
	else
		return FALSE;
}

/*
Disabling file system redirection affects only operations made by the current thread.
*/
BOOL DisWow64FsR(void)
{
#ifdef _WIN64
	return TRUE;
#else
	typedef BOOL(WINAPI *PFN_WOW64DISABLEWOW64FSREDIRECTION)(PVOID *OldValue);
	PFN_WOW64DISABLEWOW64FSREDIRECTION pfnWow64DisableWow64FsRedirection = NULL;
	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (!hKernel32) return FALSE;
	pfnWow64DisableWow64FsRedirection = (PFN_WOW64DISABLEWOW64FSREDIRECTION)
		GetProcAddress(hKernel32, "Wow64DisableWow64FsRedirection");
	if (pfnWow64DisableWow64FsRedirection) {
		PVOID OldValue = NULL;
		if (!pfnWow64DisableWow64FsRedirection(&OldValue)) return FALSE;
		else return TRUE;
	}
	else return FALSE;
#endif
}

std::string get_win32lftime_by_ft(PFILETIME ft)
{
	FILETIME ftLocal;
	SYSTEMTIME st;
	FileTimeToLocalFileTime(ft, &ftLocal);
	FileTimeToSystemTime(&ftLocal, &st);
	char lftime[32] = { 0 };
	sprintf_s(lftime, "%04d-%02d-%02d %02d:%02d:%02d",
		st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
	return lftime;
}