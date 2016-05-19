#include "ox_db.h"

int _db_ssdb_exist(redisContext *c, const char *cache_key)
{
  int rst = -1;
  if(c == NULL) {
    return rst;
  }

  redisReply *r = (redisReply *)redisCommand(c, "EXISTS %s", cache_key);
  //处理断掉重连接
  if (r == NULL) {
    freeReplyObject(r);
    free(c);
    c = redisConnect(vars.ssdb_ip, vars.ssdb_port);
    LOG_PRINT(LOG_DEBUG, "Try to reconnect ssdb.....");
  }
  if (r && r->type != REDIS_REPLY_NIL && r->type == REDIS_REPLY_INTEGER && r->integer == 1) {
    LOG_PRINT(LOG_DEBUG, "ssdb key %s exist %d", cache_key, r->integer);
    rst = 1;
  }

  freeReplyObject(r);
  return rst;
}

int ox_db_exist(thr_arg_t *thr_arg, const char *cache_key)
{
  int result = -1;
  if(vars.mode == 3) {
    if(_db_ssdb_exist(thr_arg->ssdb_conn, cache_key) == 1) {
      result = 1;
    }
    else {
      LOG_PRINT(LOG_DEBUG, "key: %s is not exist!", cache_key);
    }
  }
  return result;
}

int _ssdb_get(redisContext* c, const char *cache_key, char **buff, size_t *len)
{
  if(c == NULL) {
    return -1;
  }

  redisReply *r = (redisReply*)redisCommand(c, "GET %s", cache_key);
  if(NULL == r) {
    LOG_PRINT(LOG_DEBUG, "Execut ssdb command failure");
    return -1;
  }
  if (r->type != REDIS_REPLY_STRING) {
    LOG_PRINT(LOG_DEBUG, "Failed to execute get [%s] from ssdb.", cache_key);
    freeReplyObject(r);
    return -1;
  }

  *len = r->len;
  *buff = (char *)malloc(r->len);
  if(buff == NULL) {
    LOG_PRINT(LOG_DEBUG, "buff malloc failed!");
    return -1;
  }
  memcpy(*buff, r->str, r->len);

  freeReplyObject(r);
  LOG_PRINT(LOG_DEBUG, "Succeed to get [%s] from ssdb. length = [%d].", cache_key, *len);

  return 1;
}

int ox_db_get(thr_arg_t *thr_arg, const char *cache_key, char **buff, size_t *len)
{
  int ret = -1;
  if(vars.mode == 3 && thr_arg->ssdb_conn != NULL) {
    ret = _ssdb_get(thr_arg->ssdb_conn, cache_key, buff, len);
  }
  return ret;
}

int _ssdb_save(redisContext* c, const char *cache_key, const char *buff, const size_t len)
{
  if(c == NULL) {
    return -1;
  }

  redisReply *r = (redisReply*)redisCommand(c, "SET %s %b", cache_key, buff, len);
  if( NULL == r) {
    LOG_PRINT(LOG_DEBUG, "Execut ssdb command failure");
    return -1;
  }
  if( !(r->type == REDIS_REPLY_STATUS && strcasecmp(r->str,"OK") == 0)) {
    LOG_PRINT(LOG_DEBUG, "Failed to execute save [%s] to ssdb: %s", cache_key, r->str);
    freeReplyObject(r);
    return -1;
  }
  freeReplyObject(r);
  LOG_PRINT(LOG_DEBUG, "Succeed to save [%s] to ssdb. length = [%d].", cache_key, len);

  return 1;
}

int ox_db_save(thr_arg_t *thr_arg, const char *cache_key, const char *buff, const size_t len)
{
  int rst = -1;

  if(vars.mode == 3) {
    rst = _ssdb_save(thr_arg->ssdb_conn, cache_key, buff, len);
  }

  return rst;
}

int _ssdb_del(redisContext* c, const char *cache_key)
{
  int rst = -1;
  if(c == NULL) {
    return rst;
  }

  redisReply *r = (redisReply*)redisCommand(c, "DEL %s", cache_key);
  if (r && r->type != REDIS_REPLY_NIL && r->type == REDIS_REPLY_INTEGER && r->integer == 1) {
    LOG_PRINT(LOG_DEBUG, "ssdb key %s deleted %d", cache_key, r->integer);
    rst = 1;
  }

  freeReplyObject(r);
  return rst;
}

int ox_db_del(thr_arg_t *thr_arg, const char *cache_key)
{
  int result = -1;
  if(vars.mode == 3) {
    if(_ssdb_del(thr_arg->ssdb_conn, cache_key) == -1) {
      LOG_PRINT(LOG_DEBUG, "delete key: %s failed!", cache_key);
    }
    else {
      result = 1;
    }
  }
  return result;
}
