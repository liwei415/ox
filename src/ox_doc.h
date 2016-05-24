#ifndef _OX_DOC_
#define _OX_DOC_

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

int ox_doc_save(thr_arg_t *thr_arg, const char *buff, const int len, char *md5);
int ox_doc_new(const char *buff, const size_t len, const char *save_name);
int ox_doc_get(ox_req_doc_t *req, evhtp_request_t *request);
int ox_doc_get_db(ox_req_doc_t *req, evhtp_request_t *request);
int ox_doc_del(ox_req_doc_t *req, evhtp_request_t *request);
int ox_doc_del_db(ox_req_doc_t *req, evhtp_request_t *request);
int ox_doc_lock(ox_req_lock_t *req, evhtp_request_t *request);
int ox_doc_lock_db(ox_req_lock_t *req, evhtp_request_t *request);

#endif
