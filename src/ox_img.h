#ifndef _OX_IMG_
#define _OX_IMG_

#include <stdio.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <wand/magick_wand.h>

#include "ox_gm.h"
#include "ox_lua.h"
#include "ox_cbs.h"
#include "ox_memc.h"
#include "ox_utils.h"
#include "ox_db.h"
#include "ox_string.h"
#include "ox_log.h"
#include "ox_md5.h"
#include "ox_common.h"

int ox_img_save(thr_arg_t *thr_arg, const char *buff, const int len, char *md5);
int ox_img_new(const char *buff, const size_t len, const char *save_name);
int ox_img_get(ox_req_img_t *req, evhtp_request_t *request);
int ox_img_get_db(ox_req_img_t *req, evhtp_request_t *request);
int ox_img_del(ox_req_img_t *req, evhtp_request_t *request);
int ox_img_del_db(ox_req_img_t *req, evhtp_request_t *request);

#endif
