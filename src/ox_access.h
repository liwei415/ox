#ifndef _OX_ACCESS_
#define _OX_ACCESS_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "ox_log.h"
#include "ox_common.h"

#define  OX_OK          0
#define  OX_ERROR      -1
#define  OX_FORBIDDEN  -2

#ifndef INADDR_NONE  /* Solaris */
#define INADDR_NONE  ((unsigned int) -1)
#endif

ox_access_conf_t * ox_access_get(const char *acc_str);
int ox_access_inet(ox_access_conf_t *cf, in_addr_t addr);
void ox_access_free(ox_access_conf_t *cf);

#endif
