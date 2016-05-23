#ifndef _OX_CBS_MOV_
#define _OX_CBS_MOV_

#include <evhtp/evhtp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <magic.h>

#include "cjson/cJSON.h"
#include "ox_utils.h"
#include "ox_db.h"
#include "ox_cbs.h"
#include "ox_string.h"
#include "ox_access.h"
#include "ox_common.h"

void ox_cbs_mov(evhtp_request_t *req, void *arg);
void ox_cbs_mov_del(evhtp_request_t *req, void *arg);


#endif
