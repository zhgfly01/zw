#ifndef _ZW_GETOPT_H
#define _ZW_GETOPT_H

#ifdef __cplusplus
extern "C" {
#endif

extern char *optarg;
extern int getopt(int argc, char * const argv[], const char * opts);

#ifdef __cplusplus
}
#endif

#endif
