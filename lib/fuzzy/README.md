# 简单用法
#include <stdio.h>
#include <string.h>
#include "fuzzy.h"

int main(void)
{
    char *pszFile = "D:\\procexp.exe";
    char szFuzzy[FUZZY_MAX_RESULT] = { 0 };

    if (!fuzzy_hash_filename(pszFile, szFuzzy))
        printf("%d:%s\n", strlen(szFuzzy), szFuzzy);
}
