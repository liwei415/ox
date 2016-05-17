#ifndef _OX_UTILS_
#define _OX_UTILS_

#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>

#include "ox_log.h"
#include "ox_string.h"
#include "ox_common.h"

int ox_file_type(const char *filename, char *type);
int ox_isfile(const char *filename);
int ox_isimg(const char *filename);
int ox_isdoc(const char *filename);
int ox_isdir(const char *path);
int ox_mkdir(const char *path);
int ox_mkdirs(const char *dir);
int ox_mkdirf(const char *filename);
int ox_ismd5(char *s);
int ox_strhash(const char *str);
int ox_genkey(char *key, char *md5, ...);

#endif
