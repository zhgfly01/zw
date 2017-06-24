#ifndef _ZW_CS_H
#define _ZW_CS_H

#include "zw_comn.h"

typedef enum _CS_CODE{
	CS_SUCCESS = 0,
	CS_ERROR,
	CS_ALLOC_ERROR,
	CS_CONV_ERROR
}CS_CODE;

ZEC_START

int ws2s(char **ppszDst, const wchar_t *pcwszSrc);
int s2ws(wchar_t **ppwszDst, const char *pcszSrc);

int ws2utf8(char **ppszDst, const wchar_t *pcwszSrc);
int utf82ws(wchar_t **ppwszDst, const char *pcszSrc);

int utf82s(char **ppszDst, const char *pcszSrc);
int s2utf8(char **ppszDst, const char *pcszSrc);

ZEC_END

/* 测试代码
setlocale(LC_CTYPE, "");
char *pszText = "中文";
wchar_t *pwszText = L"测试";

char *pszDst = NULL;
ws2s(&pszDst, pwszText);
printf("%s, len:%d\n", pszDst, strlen(pszDst));
FREE_NUL(pszDst);

wchar_t *pwszDst = NULL;
s2ws(&pwszDst, pszText);
printf("%ws, len:%d\n", pwszDst, wcslen(pwszDst));
FREE_NUL(pwszDst);

char *pszUDst = NULL;
char *pszU = NULL;
s2utf8(&pszU, pszText);
utf82s(&pszUDst, pszU);
printf("UTF8: %s, len:%d\n", pszUDst, strlen(pszUDst));
FREE_NUL(pszU);
FREE_NUL(pszUDst);
*/

#endif
