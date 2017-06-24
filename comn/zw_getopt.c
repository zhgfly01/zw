#include "zw_getopt.h"
#include <string.h>

char *optarg;

int getopt(int argc, char * const argv[], const char * opts)
{
	static int optind = 1;
	static int sp = 1;
	register int c;
	register char *cp;

	if (sp == 1) {
		if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0')
			return -1;
		else if (strcmp(argv[optind], "--") == 0) {
			optind++;
			return -1;
		}
		c = argv[optind][sp];
		if (c == ':' || (cp = strchr(opts, c)) == 0) {
			if (argv[optind][++sp] == '\0') {
				optind++;
				sp = 1;
			}
			return '?';
		}
		if (*++cp == ':') {
			if (argv[optind][sp + 1] != '\0') {
				optarg = &argv[optind++][sp + 1];
			}
			else if (++optind >= argc) {
				sp = 1;
				return '?';
			}
			else {
				optarg = argv[optind++];
			}
			sp = 1;
		}
		else {
			if (argv[optind][++sp] == '\0') {
				sp = 1;
				optind++;
			}
			optarg = 0;
		}
		return c;
	}
	return -1;
}