#ifndef _OX_MEMC_
#define _OX_MEMC_

#include <libmemcached/memcached.h>

#include "ox_utils.h"
#include "ox_string.h"
#include "ox_log.h"
#include "ox_common.h"

void ox_memc_retry(thr_arg_t *thr_arg);
int ox_memc_exist(thr_arg_t *thr_arg, const char *key);
int ox_memc_get(memcached_st *memc, const char *key, char *value);
int ox_memc_set(memcached_st *memc, const char *key, const char *value);
int ox_memc_get_bin(thr_arg_t *thr_arg, const char *key, char **value_ptr, size_t *len);
int ox_memc_set_bin(thr_arg_t *thr_arg, const char *key, const char *value, const size_t len);
int ox_memc_del(thr_arg_t *thr_arg, const char *key);

#endif
