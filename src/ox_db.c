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

int _db_exist(thr_arg_t *thr_arg, const char *cache_key)
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

int ox_db_get_mode(ox_req_t *req, evhtp_request_t *request)
{
  int result = -1;
  char rsp_cache_key[CACHE_KEY_SIZE];
  char *buff = NULL;
  char *orig_buff = NULL;
  size_t img_size;
  MagickWand *im = NULL;
  bool to_save = true;

  LOG_PRINT(LOG_DEBUG, "_ox_db_get_mode() start processing ox request...");
  if(_db_exist(req->thr_arg, req->md5) == -1) {
    LOG_PRINT(LOG_DEBUG, "Image [%s] is not existed.", req->md5);
    goto err;
  }

  if(vars.script_on == 1 && req->type != NULL) {
    snprintf(rsp_cache_key, CACHE_KEY_SIZE, "%s:%s", req->md5, req->type);
  }
  else {
    if(req->proportion == 0 && req->width == 0 && req->height == 0) {
      ox_strlcpy(rsp_cache_key, req->md5, CACHE_KEY_SIZE);
    }
    else {
      ox_genkey(rsp_cache_key, req->md5, 9, req->width, req->height, req->proportion, req->gray, req->x, req->y, req->rotate, req->quality, req->fmt);
    }
  }

  if(ox_memc_get_bin(req->thr_arg, rsp_cache_key, &buff, &img_size) == 1) {
    LOG_PRINT(LOG_DEBUG, "Hit Cache[Key: %s].", rsp_cache_key);
    to_save = false;
    goto done;
  }

  LOG_PRINT(LOG_DEBUG, "Start to Find the Image...");
  if(ox_db_get(req->thr_arg, rsp_cache_key, &buff, &img_size) == 1) {
    LOG_PRINT(LOG_DEBUG, "Get image [%s] from backend db succ.", rsp_cache_key);
    if(img_size < CACHE_MAX_SIZE) {
      ox_memc_set_bin(req->thr_arg, rsp_cache_key, buff, img_size);
    }
    to_save = false;
    goto done;
  }

  im = NewMagickWand();
  if (im == NULL) {
    goto err;
  }

  if(ox_memc_get_bin(req->thr_arg, req->md5, &orig_buff, &img_size) == -1) {
    if(ox_db_get(req->thr_arg, req->md5, &orig_buff, &img_size) == -1) {
      LOG_PRINT(LOG_DEBUG, "Get image [%s] from backend db failed.", req->md5);
      goto err;
    }
    else if(img_size < CACHE_MAX_SIZE) {
      ox_memc_set_bin(req->thr_arg, req->md5, orig_buff, img_size);
    }
  }

  result = MagickReadImageBlob(im, (const unsigned char *)orig_buff, img_size);
  if (result != MagickTrue) {
    LOG_PRINT(LOG_DEBUG, "Webimg Read Blob Failed!");
    goto err;
  }
  if(vars.script_on == 1 && req->type != NULL) {
    result = ox_lua_convert(im, req);
  }
  else {
    result = ox_gm_convert(im, req);
  }

  if(result == -1) {
    goto err;
  }

  if(result == 0) {
    to_save = false;
  }

  buff = (char *)MagickWriteImageBlob(im, &img_size);
  if (buff == NULL) {
    LOG_PRINT(LOG_DEBUG, "Webimg Get Blob Failed!");
    goto err;
  }

  if(img_size < CACHE_MAX_SIZE) {
    ox_memc_set_bin(req->thr_arg, rsp_cache_key, buff, img_size);
  }

 done:
  if(vars.etag == 1) {
    result = ox_cbs_etag_set(request, buff, img_size);
    if(result == 2) {
      goto err;
    }
  }
  result = evbuffer_add(request->buffer_out, buff, img_size);
  if(result != -1) {
    int save_new = 0;
    if(to_save == true) {
      if(req->sv == 1 || vars.save_new == 1 || (vars.save_new == 2 && req->type != NULL)) {
        save_new = 1;
      }
    }

    if(save_new == 1) {
      LOG_PRINT(LOG_DEBUG, "Image [%s] Saved to Storage.", rsp_cache_key);
      ox_db_save(req->thr_arg, rsp_cache_key, buff, img_size);
    }
    else {
      LOG_PRINT(LOG_DEBUG, "Image [%s] Needn't to Storage.", rsp_cache_key);
    }
    result = 1;
  }

 err:
  if(im != NULL) {
    DestroyMagickWand(im);
  }

  free(buff);
  free(orig_buff);
  return result;
}

int ox_db_get_doc_mode(ox_req_t *req, evhtp_request_t *request)
{
  int result = -1;
  char rsp_cache_key[CACHE_KEY_SIZE];
  char *buff = NULL;
  char *orig_buff = NULL;
  size_t doc_size;

  LOG_PRINT(LOG_DEBUG, "_ox_db_get_doc_mode() start processing ox request...");
  if(_db_exist(req->thr_arg, req->md5) == -1) {
    LOG_PRINT(LOG_DEBUG, "Image [%s] is not existed.", req->md5);
    goto err;
  }
  ox_strlcpy(rsp_cache_key, req->md5, CACHE_KEY_SIZE);

  LOG_PRINT(LOG_DEBUG, "Start to Find the Doc...");
  if(ox_db_get(req->thr_arg, rsp_cache_key, &buff, &doc_size) == 1) {
    LOG_PRINT(LOG_DEBUG, "Get doc [%s] from backend db succ.", rsp_cache_key);
  }
  result = evbuffer_add(request->buffer_out, buff, doc_size);

 err:
  free(buff);
  free(orig_buff);

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

int _ssdb_exist(redisContext* c, const char *cache_key)
{
  int rst = -1;
  if(c == NULL) {
    return rst;
  }

  redisReply *r = (redisReply*)redisCommand(c, "EXISTS %s", cache_key);
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
    if(_ssdb_exist(thr_arg->ssdb_conn, cache_key) == 1) {
      result = 1;
    }
    else {
      LOG_PRINT(LOG_DEBUG, "key: %s is not exist!", cache_key);
    }
  }
  return result;
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

int del_db(thr_arg_t *thr_arg, const char *cache_key)
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
