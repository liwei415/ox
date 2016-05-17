#ifndef _OX_STRING_
#define _OX_STRING_

#include <stdlib.h>
#include <string.h>

char *ox_strnchr(const char *p, char c, size_t n);
char *ox_strnstr(const char *s, const char *find, size_t slen);
size_t ox_strlcat(char *dst, const char *src, size_t size);
size_t ox_strlcpy(char *dst, const char *src, size_t size);

#endif
