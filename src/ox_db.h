#ifndef _OX_DB_
#define _OX_DB_

#include <string.h>
#include <hiredis/hiredis.h>
#include <wand/magick_wand.h>

#include "cjson/cJSON.h"
#include "ox_lua.h"
#include "ox_cbs.h"
#include "ox_memc.h"
#include "ox_utils.h"
#include "ox_string.h"
#include "ox_common.h"

int ox_db_get_mode(ox_req_t *req, evhtp_request_t *request);
int ox_db_get(thr_arg_t *thr_arg, const char *cache_key, char **buff, size_t *len);
int ox_db_save(thr_arg_t *thr_arg, const char *cache_key, const char *buff, const size_t len);
int ox_db_exist(thr_arg_t *thr_arg, const char *cache_key);
int ox_db_del(thr_arg_t *thr_arg, const char *cache_key);

#endif
