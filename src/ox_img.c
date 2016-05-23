#include "ox_img.h"

int ox_img_save(thr_arg_t *thr_arg, const char *buff, const int len, char *md5)
{
    int result = -1;

    LOG_PRINT(LOG_DEBUG, "Begin to Caculate MD5...");
    md5_state_t mdctx;
    md5_byte_t md_value[16];
    char md5sum[33];
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

    // 存储ssdb
    if(vars.mode == 3) {
      if(ox_db_exist(thr_arg, md5sum) == 1) {
        LOG_PRINT(LOG_DEBUG, "File Exist, Needn't Save.");
        result = 1;
        goto done;
      }
      LOG_PRINT(LOG_DEBUG, "ox_db_exist not found. Begin to Save File.");

      if(ox_db_save(thr_arg, md5sum, buff, len) == -1) {
        LOG_PRINT(LOG_DEBUG, "save_img_db failed.");
        goto done;
      }
      else {
        LOG_PRINT(LOG_DEBUG, "save_img_db succ.");
        result = 1;
        goto done;
      }
    }

    //caculate 2-level path
    int lvl1 = ox_strhash(md5sum);
    int lvl2 = ox_strhash(md5sum + 3);

    snprintf(save_path, 512, "%s/%d/%d/%s", vars.img_path, lvl1, lvl2, md5sum);
    LOG_PRINT(LOG_DEBUG, "save_path: %s", save_path);

    if(ox_isdir(save_path) != 1) {
      if(ox_mkdirs(save_path) == -1) {
        LOG_PRINT(LOG_DEBUG, "save_path[%s] Create Failed!", save_path);
        goto done;
      }
      LOG_PRINT(LOG_DEBUG, "save_path[%s] Create Finish.", save_path);
    }

    snprintf(save_name, 512, "%s/0*0", save_path);
    LOG_PRINT(LOG_DEBUG, "save_name-->: %s", save_name);

    if(ox_isfile(save_name) == 1) {
      LOG_PRINT(LOG_DEBUG, "Check File Exist. Needn't Save.");
      goto cache;
    }

    if(ox_img_new(buff, len, save_name) == -1) {
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

int ox_img_new(const char *buff, const size_t len, const char *save_name)
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

int ox_img_get(ox_req_img_t *req, evhtp_request_t *request)
{
  int result = -1;
  char rsp_cache_key[CACHE_KEY_SIZE];
  int fd = -1;
  struct stat f_stat;
  char *buff = NULL;
  char *orig_buff = NULL;
  MagickWand *im = NULL;
  size_t len = 0;
  bool to_save = true;

  LOG_PRINT(LOG_DEBUG, "ox_img_get() start processing ox request...");

  int lvl1 = ox_strhash(req->md5);
  int lvl2 = ox_strhash(req->md5 + 3);

  char whole_path[512];
  snprintf(whole_path, 512, "%s/%d/%d/%s", vars.img_path, lvl1, lvl2, req->md5);
  LOG_PRINT(LOG_DEBUG, "whole_path: %s", whole_path);

  if(ox_isdir(whole_path) == -1) {
    LOG_PRINT(LOG_DEBUG, "Image %s is not existed!", req->md5);
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

  if(ox_memc_get_bin(req->thr_arg, rsp_cache_key, &buff, &len) == 1) {
    LOG_PRINT(LOG_DEBUG, "Hit Cache[Key: %s].", rsp_cache_key);
    to_save = false;
    goto done;
  }
  LOG_PRINT(LOG_DEBUG, "Start to Find the Image...");

  char orig_path[512];
  snprintf(orig_path, 512, "%s/0*0", whole_path);
  LOG_PRINT(LOG_DEBUG, "0rig File Path: %s", orig_path);

  char rsp_path[512];
  if(vars.script_on == 1 && req->type != NULL) {
    snprintf(rsp_path, 512, "%s/t_%s", whole_path, req->type);
  }
  else {
    char name[128];
    snprintf(name, 128, "%d*%d_p%d_g%d_%d*%d_r%d_q%d.%s", req->width, req->height,
             req->proportion,
             req->gray,
             req->x,
             req->y,
             req->rotate,
             req->quality,
             req->fmt);

    if(req->width == 0 && req->height == 0 && req->proportion == 0) {
      LOG_PRINT(LOG_DEBUG, "Return original image.");
      strncpy(rsp_path, orig_path, 512);
    }
    else {
      snprintf(rsp_path, 512, "%s/%s", whole_path, name);
    }
  }
  LOG_PRINT(LOG_DEBUG, "Got the rsp_path: %s", rsp_path);

  if((fd = open(rsp_path, O_RDONLY)) == -1) {
    im = NewMagickWand();
    if (im == NULL) {
      goto err;
    }

    int ret;
    if(ox_memc_get_bin(req->thr_arg, req->md5, &orig_buff, &len) == 1) {
      LOG_PRINT(LOG_DEBUG, "Hit Orignal Image Cache[Key: %s].", req->md5);

      ret = MagickReadImageBlob(im, (const unsigned char *)orig_buff, len);
      if (ret != MagickTrue) {
        LOG_PRINT(LOG_DEBUG, "Open Original Image From Blob Failed! Begin to Open it From Disk.");
        ox_memc_del(req->thr_arg, req->md5);
        ret = MagickReadImage(im, orig_path);
        if (ret != MagickTrue) {
          LOG_PRINT(LOG_DEBUG, "Open Original Image From Disk Failed!");
          goto err;
        }
        else {
          MagickSizeType size = MagickGetImageSize(im);
          LOG_PRINT(LOG_DEBUG, "image size = %d", size);
          if(size < CACHE_MAX_SIZE) {
            MagickResetIterator(im);
            char *new_buff = (char *)MagickWriteImageBlob(im, &len);
            if (new_buff == NULL) {
              LOG_PRINT(LOG_DEBUG, "Webimg Get Original Blob Failed!");
              goto err;
            }
            ox_memc_set_bin(req->thr_arg, req->md5, new_buff, len);
            free(new_buff);
          }
        }
      }
    }
    else {
      LOG_PRINT(LOG_DEBUG, "Not Hit Original Image Cache. Begin to Open it.");
      ret = MagickReadImage(im, orig_path);
      if (ret != MagickTrue) {
        LOG_PRINT(LOG_DEBUG, "Open Original Image From Disk Failed! %d != %d", ret, MagickTrue);
        LOG_PRINT(LOG_DEBUG, "Open Original Image From Disk Failed!");
        goto err;
      }
      else {
        MagickSizeType size = MagickGetImageSize(im);
        LOG_PRINT(LOG_DEBUG, "image size = %d", size);
        if(size < CACHE_MAX_SIZE) {
          MagickResetIterator(im);
          char *new_buff = (char *)MagickWriteImageBlob(im, &len);
          if (new_buff == NULL) {
            LOG_PRINT(LOG_DEBUG, "Webimg Get Original Blob Failed!");
            goto err;
          }
          ox_memc_set_bin(req->thr_arg, req->md5, new_buff, len);
          free(new_buff);
        }
      }
    }

    if(vars.script_on == 1 && req->type != NULL) {
      ret = ox_lua_convert(im, req);
    }
    else {
      ret = ox_gm_convert(im, req);
    }
    if(ret == -1) {
      goto err;
    }
    if(ret == 0) {
      to_save = false;
    }

    buff = (char *)MagickWriteImageBlob(im, &len);
    if (buff == NULL) {
      LOG_PRINT(LOG_DEBUG, "Webimg Get Blob Failed!");
      goto err;
    }
  }
  else {
    to_save = false;
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
    LOG_PRINT(LOG_DEBUG, "img_size = %d", len);
    if((rlen = read(fd, buff, len)) == -1) {
      LOG_PRINT(LOG_DEBUG, "File[%s] Read Failed: %s", rsp_path, strerror(errno));
      goto err;
    }
    else if(rlen < len) {
      LOG_PRINT(LOG_DEBUG, "File[%s] Read Not Compeletly.", rsp_path);
      goto err;
    }
  }

  //LOG_PRINT(LOG_INFO, "New Image[%s]", rsp_path);
  int save_new = 0;
  if(to_save == true) {
    if(req->sv == 1 || vars.save_new == 1 || (vars.save_new == 2 && req->type != NULL)) {
      save_new = 1;
    }
  }

  if(save_new == 1) {
    LOG_PRINT(LOG_DEBUG, "Image[%s] is Not Existed. Begin to Save it.", rsp_path);
    if(ox_img_new(buff, len, rsp_path) == -1) {
      LOG_PRINT(LOG_DEBUG, "New Image[%s] Save Failed!", rsp_path);
      LOG_PRINT(LOG_WARNING, "fail save %s", rsp_path);
    }
  }
  else {
    LOG_PRINT(LOG_DEBUG, "Image [%s] Needn't to Storage.", rsp_path);
  }

  if(len < CACHE_MAX_SIZE) {
    ox_memc_set_bin(req->thr_arg, rsp_cache_key, buff, len);
  }

 done:
  if(vars.etag == 1) {
    result = ox_cbs_etag_set(request, buff, len);
    if(result == 2) {
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
  if(im != NULL) {
    DestroyMagickWand(im);
  }
  free(buff);
  free(orig_buff);

  return result;
}

int ox_img_get_db(ox_req_img_t *req, evhtp_request_t *request)
{
  int result = -1;
  char rsp_cache_key[CACHE_KEY_SIZE];
  char *buff = NULL;
  char *orig_buff = NULL;
  size_t img_size;
  MagickWand *im = NULL;
  bool to_save = true;

  LOG_PRINT(LOG_DEBUG, "_ox_get_img_db() start processing ox request...");
  if(ox_db_exist(req->thr_arg, req->md5) == -1) {
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


int ox_img_del(ox_req_img_t *req, evhtp_request_t *request)
{
  int result = -1;

  LOG_PRINT(LOG_DEBUG, "_img_del() start processing admin request...");
  char whole_path[512];
  int lvl1 = ox_strhash(req->md5);
  int lvl2 = ox_strhash(req->md5 + 3);
  snprintf(whole_path, 512, "%s/%d/%d/%s", vars.img_path, lvl1, lvl2, req->md5);
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

int ox_img_del_db(ox_req_img_t *req, evhtp_request_t *request)
{
  int result = -1;

  LOG_PRINT(LOG_DEBUG, "ox_img_del_db() start processing admin request...");

  char cache_key[CACHE_KEY_SIZE];
  ox_strlcpy(cache_key, req->md5, CACHE_KEY_SIZE);
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
