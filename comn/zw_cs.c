#include "zw_cs.h"

static int ws2s_t(char **ppszDst, const wchar_t *pcwszSrc, UINT uCodePage)
{
	int iLen = 0;
	if (!pcwszSrc) return CS_ERROR;
	iLen = WideCharToMultiByte(uCodePage, 0, pcwszSrc, -1, 0, 0, 0, 0);
	if (!iLen) return CS_CONV_ERROR;
	*ppszDst = (char *)malloc(iLen);
	if (!*ppszDst) return CS_ALLOC_ERROR;
	if (!WideCharToMultiByte(uCodePage, 0, pcwszSrc, -1, *ppszDst, iLen, 0, 0)) {
		FREE_NUL(*ppszDst);
		return CS_CONV_ERROR;
	}
	else return CS_SUCCESS;
}
static int s2ws_t(wchar_t **ppwszDst, const char *pcszSrc, UINT uCodePage)
{
	int iLen = 0;
	if (!pcszSrc) return CS_ERROR;
	iLen = MultiByteToWideChar(uCodePage, 0, pcszSrc, -1, 0, 0);
	if (!iLen) return CS_CONV_ERROR;
	*ppwszDst = (wchar_t *)malloc(iLen * sizeof(wchar_t));
	if (!*ppwszDst) return CS_ALLOC_ERROR;
	if (!MultiByteToWideChar(uCodePage, 0, pcszSrc, -1, *ppwszDst, iLen)) {
		FREE_NUL(*ppwszDst);
		return CS_CONV_ERROR;
	}
	else return CS_SUCCESS;
}

int ws2s(char **ppszDst, const wchar_t *pcwszSrc)
{
	return ws2s_t(ppszDst, pcwszSrc, CP_ACP);
}
int s2ws(wchar_t **ppwszDst, const char *pcszSrc)
{
	return s2ws_t(ppwszDst, pcszSrc, CP_ACP);
}

int ws2utf8(char **ppszDst, const wchar_t *pcwszSrc)
{
	return ws2s_t(ppszDst, pcwszSrc, CP_UTF8);
}
int utf82ws(wchar_t **ppwszDst, const char *pcszSrc)
{
	return s2ws_t(ppwszDst, pcszSrc, CP_UTF8);
}

int utf82s(char **ppszDst, const char *pcszSrc)
{
	wchar_t *pwszTmp = NULL;
	int iRetVal = 0;
	iRetVal = utf82ws(&pwszTmp, pcszSrc);
	if (iRetVal) return CS_ERROR;
	iRetVal = ws2s(ppszDst, pwszTmp);
	FREE_NUL(pwszTmp);
	return iRetVal;
}
int s2utf8(char **ppszDst, const char *pcszSrc)
{
	wchar_t *pwszTmp = NULL;
	int iRetVal = 0;
	iRetVal = s2ws(&pwszTmp, pcszSrc);
	if (iRetVal) return CS_ERROR;
	iRetVal = ws2utf8(ppszDst, pwszTmp);
	FREE_NUL(pwszTmp);
	return iRetVal;
}