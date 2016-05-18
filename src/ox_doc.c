#include "ox_doc.h"

int ox_doc_save(thr_arg_t *thr_arg, const char *buff, const int len, char *md5)
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

    if(vars.mode != 1) {
      if(ox_db_exist(thr_arg, md5sum) == 1) {
        LOG_PRINT(LOG_DEBUG, "File Exist, Needn't Save.");
        result = 1;
        goto done;
      }
      LOG_PRINT(LOG_DEBUG, "ox_db_exist not found. Begin to Save File.");

      if(ox_db_save(thr_arg, md5sum, buff, len) == -1) {
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
