#ifndef _OX_MOV_
#define _OX_MOV_

#include <stdio.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <wand/magick_wand.h>

#include "ox_lua.h"
#include "ox_cbs.h"
#include "ox_memc.h"
#include "ox_utils.h"
#include "ox_db.h"
#include "ox_string.h"
#include "ox_log.h"
#include "ox_md5.h"
#include "ox_common.h"

int ox_mov_save(thr_arg_t *thr_arg, const char *buff, const int len, char *md5);
int ox_mov_new(const char *buff, const size_t len, const char *save_name);
int ox_mov_get(ox_req_mov_t *req, evhtp_request_t *request);
int ox_mov_get_db(ox_req_mov_t *req, evhtp_request_t *request);
int ox_mov_del(ox_req_mov_t *req, evhtp_request_t *request);
int ox_mov_del_db(ox_req_mov_t *req, evhtp_request_t *request);
int ox_mov_lock(ox_req_lock_t *req, evhtp_request_t *request);
int ox_mov_lock_db(ox_req_lock_t *req, evhtp_request_t *request);

#endif
