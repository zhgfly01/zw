#include <stdio.h>
#include "zw_proc_infos.h"

int main(void)
{
	if (!InitProcEnvVars()) {
		fprintf(stderr, "InitProcEnvVars error\n");
		exit(EXIT_FAILURE);
	}
	if (!DisWow64FsR()) {
		fprintf(stderr, "DisWow64FsR error\n");
		exit(EXIT_FAILURE);
	}

	MAP_PSS *pss = NULL;
	pss = new MAP_PSS();
	if (!pss)
		exit(EXIT_FAILURE);
	if (!GetProcInfoBySnapshot(*pss)) {
		fprintf(stderr, "GetProcInfoBySnapshot error\n");
		goto END;
	}

	for (MAP_PSS::iterator it = pss->begin(); it != pss->end(); it++) {
		printf("%d\t%d\t%s\t%d\n", it->second->pid, it->second->ppid, 
			it->second->exe_name.c_str(), it->second->exe_bit);
		printf("\t%s\n", it->second->exe_path.c_str());
		printf("\t%s\n", it->second->stime.c_str());

		/*		for (SET_STR::iterator sit = it->second->modules.begin();
		sit != it->second->modules.end(); sit++) {
		printf("\t%s\n", sit->c_str());
		}*/
	}

END:
	if (pss) {
		for (MAP_PSS::iterator mpit = pss->begin(); mpit != pss->end(); mpit++) {
			if (mpit->second)
				delete mpit->second;
		}
		delete pss;
	}
	
	return 0;
}