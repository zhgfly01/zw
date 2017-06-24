#ifndef _ZW_COMN_H
#define _ZW_COMN_H

#include <Windows.h>

#ifdef __cplusplus
# define ZEC_START extern "C" {
# define ZEC_END }
#else
# define ZEC_START
# define ZEC_END
#endif

#if defined(UNICODE) || defined(_UNICODE)
#define _T(x) L##x
#else
#define _T(x) x
#endif

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

#define FREE_NUL(ptr) {free(ptr);ptr=NULL;}

#include <string>
#include <vector>
#include <map>
#include <set>

typedef std::vector<std::string> VEC_STR;
typedef std::map<std::string, std::string> MAP_STR;
typedef std::set<std::string> SET_STR;

#include <process.h>
typedef unsigned (__stdcall *PTHREAD_START)(void *);
#define PFNBTEX(psa, dwStackSize, pfnStartAddr, pvParam, dwFlags, pdwTid) \
	((HANDLE)_beginthreadex(			\
		(void *)(psa),					\
		(unsigned)(dwStackSize),		\
		(PTHREAD_START)(pfnStartAddr),	\
		(void *)(pvParam),				\
		(unsigned)(dwFlags),			\
		(unsigned *)(pdwTid)))

#define FIELD_OFFSET32(type, field)		((ULONG)&(((type *)0)->field))
#define FIELD_OFFSET64(type, field)		((ULONG64)&(((type *)0)->field))
#define CONTAINING_RECORD32(address, type, field)	((type *)( \
													(PCHAR)(address) - \
													(ULONG)(&((type *)0)->field)))
#define CONTAINING_RECORD64(address, type, field)	((type *)( \
													(PCHAR)(address) - \
													(ULONG64)(&((type *)0)->field)))
#ifdef _WIN64
#define FIELD_OFFSET_T FIELD_OFFSET64
#define CONTAINING_RECORD_T CONTAINING_RECORD64
#else
#define FIELD_OFFSET_T FIELD_OFFSET32
#define CONTAINING_RECORD_T CONTAINING_RECORD32
#endif


typedef enum _ZW_CODE{
	ZW_ERROR = -1,
	ZW_SUCCESS = 0,
}ZW_CODE;

extern const char *pcszAppPath;
BOOL GetAppPath(void);

typedef void(*PFN_TDCALLBACK)(const char *pcszFilePath);
void WalkDir(
	const char *pcszDirPath,
	int bSub,
	const char *pcszWildcard,
	PFN_TDCALLBACK pfnCallBack
	);

BOOL DebugPrivilege(BOOL bEnable);

BOOL Is64BitOS(void);

BOOL DisWow64FsR(void);

#endif
