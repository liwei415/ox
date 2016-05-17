#include "ox_memc.h"

void ox_memc_retry(thr_arg_t *thr_arg)
{
  if(thr_arg->cache_conn != NULL) {
    memcached_free(thr_arg->cache_conn);
  }

  memcached_st *memc;
  memc= memcached_create(NULL);

  char mserver[32];
  snprintf(mserver, 32, "%s:%d", vars.cache_ip, vars.cache_port);
  memcached_server_st *servers = memcached_servers_parse(mserver);

  memcached_server_push(memc, servers);
  memcached_server_list_free(servers);
  memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL, 1);
  memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_NO_BLOCK, 1);
  memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_NOREPLY, 1);
  memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_TCP_KEEPALIVE, 1);
  thr_arg->cache_conn = memc;

  evthr_set_aux(thr_arg->thread, thr_arg);
}

int ox_memc_exist(thr_arg_t *thr_arg, const char *key)
{
  int rst = -1;
  if(vars.cache_on == false) {
    return rst;
  }
  if(thr_arg->cache_conn == NULL) {
    return rst;
  }

  memcached_st *memc = thr_arg->cache_conn;
  memcached_return rc;

  size_t valueLen = 0;
  uint32_t flags;
  char *value = memcached_get(memc, key, strlen(key), &valueLen, &flags, &rc);
  //rc = memcached_exist(memc, key, strlen(key));

  if (rc == MEMCACHED_SUCCESS) {
    LOG_PRINT(LOG_DEBUG, "Cache Key[%s] Exist.", key);
    rst = 1;
  }
  else if(rc == MEMCACHED_CONNECTION_FAILURE) {
    LOG_PRINT(LOG_DEBUG, "Cache Conn Failed!");
    //retry_cache(thr_arg);
  }
  else {
    const char *str_rc = memcached_strerror(memc, rc);
    LOG_PRINT(LOG_DEBUG, "Cache Result: %s", str_rc);
  }
  free(value);

  return rst;
}

int ox_memc_get(memcached_st *memc, const char *key, char *value)
{
  int rst = -1;
  if(memc == NULL) {
    return rst;
  }

  size_t valueLen;
  uint32_t flags;
  memcached_return rc;

  char *pvalue = memcached_get(memc, key, strlen(key), &valueLen, &flags, &rc);

  if (rc == MEMCACHED_SUCCESS) {
    LOG_PRINT(LOG_DEBUG, "Cache Find Key[%s] Value: %s", key, pvalue);
    ox_strlcpy(value, pvalue, sizeof(value));
    free(pvalue);
    rst = 1;
  }
  else if (rc == MEMCACHED_NOTFOUND) {
    LOG_PRINT(LOG_DEBUG, "Cache Key[%s] Not Find!", key);
    rst = -1;
  }
  else {
    const char *str_rc = memcached_strerror(memc, rc);
    LOG_PRINT(LOG_DEBUG, "Cache Result: %s", str_rc);
  }

  return rst;
}

int ox_memc_set(memcached_st *memc, const char *key, const char *value)
{
  int rst = -1;
  if(memc == NULL) {
    return rst;
  }

  memcached_return rc;

  rc = memcached_set(memc, key, strlen(key), value, strlen(value), 0, 0);

  if (rc == MEMCACHED_SUCCESS) {
    LOG_PRINT(LOG_DEBUG, "Cache Set Successfully. Key[%s] Value: %s", key, value);
    rst = 1;
  }
  else if(rc == MEMCACHED_CONNECTION_FAILURE) {
    LOG_PRINT(LOG_DEBUG, "Cache Connection Failed!");
  }
  else {
    LOG_PRINT(LOG_DEBUG, "Cache Set(Key: %s Value: %s) Failed!", key, value);
    const char *str_rc = memcached_strerror(memc, rc);
    LOG_PRINT(LOG_DEBUG, "Cache Result: %s", str_rc);
    rst = -1;
  }

  return rst;
}

int ox_memc_get_bin(thr_arg_t *thr_arg, const char *key, char **value_ptr, size_t *len)
{
  int rst = -1;
  if(vars.cache_on == false) {
    return rst;
  }
  if(thr_arg->cache_conn == NULL) {
    LOG_PRINT(LOG_DEBUG, "thr_arg->cache_conn nil.");
    return rst;
  }

  uint32_t flags;
  memcached_st *memc = thr_arg->cache_conn;
  memcached_return rc;

  *value_ptr = memcached_get(memc, key, strlen(key), len, &flags, &rc);

  if (rc == MEMCACHED_SUCCESS) {
    LOG_PRINT(LOG_DEBUG, "Binary Cache Find Key[%s], Len: %d.", key, *len);
    rst = 1;
  }
  else if(rc == MEMCACHED_CONNECTION_FAILURE) {
    LOG_PRINT(LOG_DEBUG, "Cache Conn Failed!");
    //retry_cache(thr_arg);
  }
  else if (rc == MEMCACHED_NOTFOUND) {
    LOG_PRINT(LOG_DEBUG, "Binary Cache Key[%s] Not Find!", key);
    rst = -1;
  }
  else {
    const char *str_rc = memcached_strerror(memc, rc);
    LOG_PRINT(LOG_DEBUG, "Cache Result: %s", str_rc);
  }

  //memcached_free(memc);
  return rst;
}

int ox_memc_set_bin(thr_arg_t *thr_arg, const char *key, const char *value, const size_t len)
{
  int rst = -1;
  if(vars.cache_on == false) {
    return rst;
  }
  if(thr_arg->cache_conn == NULL) {
    return rst;
  }

  memcached_st *memc = thr_arg->cache_conn;
  memcached_return rc;

  rc = memcached_set(memc, key, strlen(key), value, len, 0, 0);

  if (rc == MEMCACHED_SUCCESS) {
    LOG_PRINT(LOG_DEBUG, "Binary Cache Set Successfully. Key[%s] Len: %d.", key, len);
    rst = 1;
  }
  else if(rc == MEMCACHED_CONNECTION_FAILURE) {
    LOG_PRINT(LOG_DEBUG, "Cache Conn Failed!");
    //retry_cache(thr_arg);
  }
  else {
    LOG_PRINT(LOG_DEBUG, "Binary Cache Set Key[%s] Failed!", key);
    const char *str_rc = memcached_strerror(memc, rc);
    LOG_PRINT(LOG_DEBUG, "Cache Result: %s", str_rc);
    rst = -1;
  }

  return rst;
}

int ox_memc_del(thr_arg_t *thr_arg, const char *key)
{
  int rst = -1;
  if(vars.cache_on == false) {
    return rst;
  }
  if(thr_arg->cache_conn == NULL) {
    return rst;
  }

  memcached_st *memc = thr_arg->cache_conn;
  memcached_return rc;

  rc = memcached_delete(memc, key, strlen(key), 0);

  if (rc == MEMCACHED_SUCCESS) {
    LOG_PRINT(LOG_DEBUG, "Cache Key[%s] Delete Successfully.", key);
    rst = 1;
  }
  else if(rc == MEMCACHED_CONNECTION_FAILURE) {
    LOG_PRINT(LOG_DEBUG, "Cache Conn Failed!");
    //retry_cache(thr_arg);
  }
  else {
    LOG_PRINT(LOG_DEBUG, "Cache Key[%s] Delete Failed!", key);
    const char *str_rc = memcached_strerror(memc, rc);
    LOG_PRINT(LOG_DEBUG, "Cache Result: %s", str_rc);
    rst = -1;
  }

  return rst;
}
