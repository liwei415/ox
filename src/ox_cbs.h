#ifndef _OX_CBS_
#define _OX_CBS_

#include <evhtp/evhtp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <magic.h>

#include "cjson/cJSON.h"
#include "ox_utils.h"
#include "ox_db.h"
#include "ox_mov.h"
#include "ox_doc.h"
#include "ox_img.h"
#include "ox_string.h"
#include "ox_access.h"
#include "ox_common.h"

typedef struct mp_arg_s mp_arg_t;
struct mp_arg_s {
  evhtp_request_t *req;
  thr_arg_t *thr_arg;
  char address[16];
  int partno;
  int succno;
  int check_name;
};

ox_cbs_headers_conf_t * ox_cbs_get_headers_conf(const char *hdr_str);
void ox_cbs_headers_free(ox_cbs_headers_conf_t *hcf);
int ox_cbs_etag_set(evhtp_request_t *req, char *buff, size_t len);
int ox_cbs_on_header_value(multipart_parser* p, const char *at, size_t length);
int ox_cbs_on_chunk_data(multipart_parser* p, const char *at, size_t length);
void ox_cbs_index(evhtp_request_t *req, void *arg);
void ox_cbs_image(evhtp_request_t *req, void *arg);
void ox_cbs_doc(evhtp_request_t *req, void *arg);
void ox_cbs_mov(evhtp_request_t *req, void *arg);

#endif
