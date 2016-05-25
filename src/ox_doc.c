#include "ox_doc.h"

int ox_doc_save(thr_arg_t *thr_arg, const char *buff, const int len, char *md5)
{
    int result = -1;

    LOG_PRINT(LOG_DEBUG, "Begin to Caculate MD5...");
    md5_state_t mdctx;
    md5_byte_t md_value[16];
    char md5sum[33];
    char ckey[40];
    int i;
    int h, l;
    md5_init(&mdctx);
    md5_append(&mdctx, (const unsigned char*)(buff), len);
    md5_finish(&mdctx, md_value);

    for(i = 0; i < 16; ++i) {
      h = md_value[i] & 0xf0;
      h >>= 4;
      l = md_value[i] & 0x0f;
      md5sum[i * 2] = (char)((h >= 0x0 && h <= 0x9) ? (h + 0x30) : (h + 0x57));
      md5sum[i * 2 + 1] = (char)((l >= 0x0 && l <= 0x9) ? (l + 0x30) : (l + 0x57));
    }
    md5sum[32] = '\0';
    ox_strlcpy(md5, md5sum, 33);
    LOG_PRINT(LOG_DEBUG, "md5: %s", md5sum);

    char save_path[512];
    char save_name[512];

    if(vars.mode == 3) {
      snprintf(ckey, 40, "DOC_%s", md5sum);
      LOG_PRINT(LOG_DEBUG, "ckey: %s", ckey);

      if(ox_db_exist(thr_arg, ckey) == 1) {
        LOG_PRINT(LOG_DEBUG, "File Exist, Needn't Save.");
        result = 1;
        goto done;
      }
      LOG_PRINT(LOG_DEBUG, "ox_db_exist not found. Begin to Save File.");

      if(ox_db_save(thr_arg, ckey, buff, len) == -1) {
        LOG_PRINT(LOG_DEBUG, "save_doc_db failed.");
        goto done;
      }
      else {
        LOG_PRINT(LOG_DEBUG, "save_doc_db succ.");
        result = 1;
        goto done;
      }
    }

    //caculate 2-level path
    int lvl1 = ox_strhash(md5sum);
    int lvl2 = ox_strhash(md5sum + 3);

    snprintf(save_path, 512, "%s/%d/%d/%s", vars.doc_path, lvl1, lvl2, md5sum);
    LOG_PRINT(LOG_DEBUG, "save_path: %s", save_path);

    if(ox_isdir(save_path) != 1) {
      if(ox_mkdirs(save_path) == -1) {
        LOG_PRINT(LOG_DEBUG, "save_path[%s] Create Failed!", save_path);
        goto done;
      }
      LOG_PRINT(LOG_DEBUG, "save_path[%s] Create Finish.", save_path);
    }

    snprintf(save_name, 512, "%s/%s", save_path, md5sum);
    LOG_PRINT(LOG_DEBUG, "save_name-->: %s", save_name);

    if(ox_isfile(save_name) == 1) {
      LOG_PRINT(LOG_DEBUG, "Check File Exist. Needn't Save.");
      goto cache;
    }

    if(ox_doc_new(buff, len, save_name) == -1) {
      LOG_PRINT(LOG_DEBUG, "Save Image[%s] Failed!", save_name);
      goto done;
    }

cache:
    if(len < CACHE_MAX_SIZE) {
      ox_memc_set_bin(thr_arg, md5sum, buff, len);
    }
    result = 1;

done:
    return result;
}

int ox_doc_new(const char *buff, const size_t len, const char *save_name)
{
  int result = -1;
  LOG_PRINT(LOG_DEBUG, "Start to Storage the New Image...");
  int fd = -1;
  int wlen = 0;

  if((fd = open(save_name, O_WRONLY | O_TRUNC | O_CREAT, 00644)) < 0) {
    LOG_PRINT(LOG_DEBUG, "fd(%s) open failed!", save_name);
    goto done;
  }

  if(flock(fd, LOCK_EX | LOCK_NB) == -1) {
    LOG_PRINT(LOG_DEBUG, "This fd is Locked by Other thread.");
    goto done;
  }

  wlen = write(fd, buff, len);
  if(wlen == -1) {
    LOG_PRINT(LOG_DEBUG, "write(%s) failed!", save_name);
    goto done;
  }
  else if(wlen < len) {
    LOG_PRINT(LOG_DEBUG, "Only part of [%s] is been writed.", save_name);
    goto done;
  }
  flock(fd, LOCK_UN | LOCK_NB);
  LOG_PRINT(LOG_DEBUG, "Image [%s] Write Successfully!", save_name);
  result = 1;

done:
  if(fd != -1) {
    close(fd);
  }
  return result;
}


int ox_doc_get(ox_req_doc_t *req, evhtp_request_t *request)
{
  int result = -1;
  int fd = -1;
  struct stat f_stat;
  char *buff = NULL;
  size_t len = 0;

  LOG_PRINT(LOG_DEBUG, "ox_doc_get() start processing ox request...");

  int lvl1 = ox_strhash(req->md5);
  int lvl2 = ox_strhash(req->md5 + 3);

  char whole_path[512];
  char whole_path_lock[512];
  char whole_path_lock_passwd[512];
  snprintf(whole_path, 512, "%s/%d/%d/%s", vars.doc_path, lvl1, lvl2, req->md5);
  snprintf(whole_path_lock, 512, "%s/%d/%d/%s/lock", vars.doc_path, lvl1, lvl2, req->md5);
  snprintf(whole_path_lock_passwd, 512, "%s/%d/%d/%s/lock.%s", vars.doc_path, lvl1, lvl2, req->md5, req->passwd);
  LOG_PRINT(LOG_DEBUG, "whole_path: %s", whole_path);

  if(ox_isdir(whole_path) == -1) {
    LOG_PRINT(LOG_DEBUG, "Image %s is not existed!", req->md5);
    goto err;
  }

  if (req->acs != OX_OK) {
    LOG_PRINT(LOG_DEBUG, "acs != OX_OK");
    if (ox_isfile(whole_path_lock) == 1 && ox_isfile(whole_path_lock_passwd) == -1) {
      LOG_PRINT(LOG_DEBUG, "lock exist and lock.passwd is not exist.");
      goto err;
    }
  }

  char rsp_path[512];
  snprintf(rsp_path, 512, "%s/%s", whole_path, req->md5);
  LOG_PRINT(LOG_DEBUG, "Got the rsp_path: %s", rsp_path);

  if((fd = open(rsp_path, O_RDONLY)) != -1) {

    fstat(fd, &f_stat);
    size_t rlen = 0;
    len = f_stat.st_size;
    if(len <= 0) {
      LOG_PRINT(LOG_DEBUG, "File[%s] is Empty.", rsp_path);
      goto err;
    }
    if((buff = (char *)malloc(len)) == NULL) {
      LOG_PRINT(LOG_DEBUG, "buff Malloc Failed!");
      goto err;
    }
    LOG_PRINT(LOG_DEBUG, "doc_size = %d", len);
    if((rlen = read(fd, buff, len)) == -1) {
      LOG_PRINT(LOG_DEBUG, "File[%s] Read Failed: %s", rsp_path, strerror(errno));
      goto err;
    }
    else if(rlen < len) {
      LOG_PRINT(LOG_DEBUG, "File[%s] Read Not Compeletly.", rsp_path);
      goto err;
    }
  }

  result = evbuffer_add(request->buffer_out, buff, len);
  if(result != -1) {
    result = 1;
  }

 err:
  if(fd != -1) {
    close(fd);
  }
  free(buff);

  return result;
}

int ox_doc_get_db(ox_req_doc_t *req, evhtp_request_t *request)
{
  int result = -1;
  char rsp_cache_key[CACHE_KEY_SIZE];
  char *buff = NULL;
  char *orig_buff = NULL;
  size_t doc_size;

  snprintf(rsp_cache_key, CACHE_KEY_SIZE, "DOC_%s", req->md5);
  LOG_PRINT(LOG_DEBUG, "ckey: %s", rsp_cache_key);

  LOG_PRINT(LOG_DEBUG, "_ox_doc_get_db() start processing ox request...");
  if(ox_db_exist(req->thr_arg, rsp_cache_key) == -1) {
    LOG_PRINT(LOG_DEBUG, "Doc [%s] is not existed.", rsp_cache_key);
    goto err;
  }

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

int ox_doc_del(ox_req_doc_t *req, evhtp_request_t *request)
{
  int result = -1;

  LOG_PRINT(LOG_DEBUG, "_doc_del() start processing admin request...");
  char whole_path[512];
  int lvl1 = ox_strhash(req->md5);
  int lvl2 = ox_strhash(req->md5 + 3);
  snprintf(whole_path, 512, "%s/%d/%d/%s", vars.doc_path, lvl1, lvl2, req->md5);
  LOG_PRINT(LOG_DEBUG, "whole_path: %s", whole_path);

  if(ox_isdir(whole_path) == -1) {
    LOG_PRINT(LOG_DEBUG, "path: %s is not exists!", whole_path);
    return 2;
  }

  if(ox_rm(whole_path) != -1) {
    result = 1;
  }
  return result;
}

int ox_doc_del_db(ox_req_doc_t *req, evhtp_request_t *request)
{
  int result = -1;

  LOG_PRINT(LOG_DEBUG, "ox_doc_del_db() start processing admin request...");

  char cache_key[CACHE_KEY_SIZE+5];
  snprintf(cache_key, 40, "DOC_%s", req->md5);
  LOG_PRINT(LOG_DEBUG, "original key: %s", cache_key);

  result = ox_db_exist(req->thr_arg, cache_key);
  if(result == -1) {
    LOG_PRINT(LOG_DEBUG, "key: %s is not exists!", req->md5);
    return 2;
  }

  if(ox_db_del(req->thr_arg, cache_key) != -1) {
    result = 1;
  }
  return result;
}

int ox_doc_lock(ox_req_lock_t *req, evhtp_request_t *request)
{
  int result = -1;

  LOG_PRINT(LOG_DEBUG, "_doc_lock() start processing admin request...");
  char whole_path[512];
  char whole_path_passwd[512];
  int lvl1 = ox_strhash(req->md5);
  int lvl2 = ox_strhash(req->md5 + 3);
  snprintf(whole_path, 512, "%s/%d/%d/%s/lock", vars.doc_path, lvl1, lvl2, req->md5);
  snprintf(whole_path, 512, "%s/%d/%d/%s/lock.%s", vars.doc_path, lvl1, lvl2, req->md5, req->passwd);
  LOG_PRINT(LOG_DEBUG, "whole_path: %s", whole_path);

  if(ox_isfile(whole_path) == 1) {
    LOG_PRINT(LOG_DEBUG, "path: %s already locked!", whole_path);
    return 2;
  }

  if(ox_mklock(whole_path, whole_path_passwd) != -1) {
    result = 1;
  }
  return result;
}

int ox_doc_lock_db(ox_req_lock_t *req, evhtp_request_t *request)
{
  int result = -1;

  LOG_PRINT(LOG_DEBUG, "ox_doc_lock_db() start processing admin request...");

  char cache_key[CACHE_KEY_SIZE];
  char cache_key_passwd[CACHE_KEY_SIZE];
  snprintf(cache_key, CACHE_KEY_SIZE, "%s.lock", req->md5);
  snprintf(cache_key_passwd, CACHE_KEY_SIZE, "%s.lock.%s", req->md5, req->passwd);
  LOG_PRINT(LOG_DEBUG, "original key: %s", cache_key);

  result = ox_db_exist(req->thr_arg, cache_key);
  if(result == -1) {
    LOG_PRINT(LOG_DEBUG, "lock key: %s is not exists!", cache_key);
    return 2;
  }

  ox_db_save(req->thr_arg, cache_key, "1", 1);
  ox_db_save(req->thr_arg, cache_key_passwd, "1", 1);

  return 1;
}

int ox_doc_unlock(ox_req_unlock_t *req, evhtp_request_t *request)
{
  int result = -1;

  LOG_PRINT(LOG_DEBUG, "_doc_lock() start processing admin request...");
  char whole_path[512];
  char whole_path_passwd[512];
  int lvl1 = ox_strhash(req->md5);
  int lvl2 = ox_strhash(req->md5 + 3);
  snprintf(whole_path, 512, "%s/%d/%d/%s/lock", vars.doc_path, lvl1, lvl2, req->md5);
  snprintf(whole_path_passwd, 512, "%s/%d/%d/%s/lock.%s", vars.doc_path, lvl1, lvl2, req->md5, req->passwd);
  LOG_PRINT(LOG_DEBUG, "whole_path: %s", whole_path);

  if (ox_isfile(whole_path) == 1 && ox_isfile(whole_path_passwd) == 1) {
    ox_rm(whole_path);
    ox_rm(whole_path_passwd);
    result = 1;
  }

  return result;
}

int ox_doc_unlock_db(ox_req_unlock_t *req, evhtp_request_t *request)
{
  int result = -1;

  LOG_PRINT(LOG_DEBUG, "ox_doc_lock_db() start processing admin request...");

  char cache_key[CACHE_KEY_SIZE];
  char cache_key_passwd[CACHE_KEY_SIZE];
  snprintf(cache_key, CACHE_KEY_SIZE, "%s.lock", req->md5);
  snprintf(cache_key_passwd, CACHE_KEY_SIZE, "%s.lock.%s", req->md5, req->passwd);
  LOG_PRINT(LOG_DEBUG, "original key: %s", cache_key);

  if (ox_db_exist(req->thr_arg, cache_key) == 1 && ox_db_exist(req->thr_arg, cache_key_passwd) == 1) {
    ox_db_del(req->thr_arg, cache_key);
    ox_db_del(req->thr_arg, cache_key_passwd);
    result = 1;
  }

  return result;
}
