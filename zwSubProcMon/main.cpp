#include <stdio.h>
#include "zwSubProcMon.h"

int main()
{
	printf("begin SubProcMon\n");
	SubProcMon(NULL, "notepad.exe");
	printf("stop SubProcMon\n");
}