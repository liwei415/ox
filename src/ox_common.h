#ifndef _OX_COMMON_
#define _OX_COMMON_

#include <stdio.h>
#include <string.h>
#include <libmemcached/memcached.h>
#include <hiredis/hiredis.h>
#include <lualib.h>
#include <magic.h>
#include <evhtp/evhtp.h>
#include "multipart-parser/multipart_parser.h"

#include "ox_log.h"

#ifndef OX_VERSION
#define OX_VERSION "1.0.0"
#endif

#define MAX_LINE            1024
#define CACHE_MAX_SIZE      1048576 //1024*1024
#define RETRY_TIME_WAIT     1000
#define CACHE_KEY_SIZE      128
#define PATH_MAX_SIZE       512

typedef struct thr_arg_s thr_arg_t;
struct thr_arg_s {
  evthr_t *thread;
  memcached_st *cache_conn;
  redisContext *ssdb_conn;
  lua_State* L;
};

typedef struct ox_req_s ox_req_t;
struct ox_req_s {
  char *md5;
  char *type;
  int width;
  int height;
  int proportion;
  int gray;
  int x;
  int y;
  int rotate;
  int quality;
  char *fmt;
  int sv;
  thr_arg_t *thr_arg;
};

typedef struct ox_cbs_header_s ox_cbs_header_t;
struct ox_cbs_header_s {
  char key[128];
  char value[512];
};

typedef struct ox_cbs_headers_s ox_cbs_headers_t;
struct ox_cbs_headers_s {
  ox_cbs_header_t *value;
  ox_cbs_headers_t *next;
};

typedef struct ox_cbs_headers_conf_s ox_cbs_headers_conf_t;
struct ox_cbs_headers_conf_s {
  uint n;
  ox_cbs_headers_t *headers;
};

// access
typedef struct ox_access_rule_s ox_access_rule_t;
struct ox_access_rule_s {
  in_addr_t mask;
  in_addr_t addr;
  uint deny;	/* unsigned  deny:1; */
};

typedef struct ox_access_rules_s ox_access_rules_t;
struct ox_access_rules_s {
    ox_access_rule_t *value;
    ox_access_rules_t *next;
};

typedef struct ox_access_conf_s ox_access_conf_t;
struct ox_access_conf_s {
  uint n;
  ox_access_rules_t *rules;
};

typedef struct ox_vars_s ox_vars_t;
struct ox_vars_s {
  lua_State *L;
  int is_daemon;
  char ip[128];
  int port;
  int num_threads;
  int backlog;
  int max_keepalives;
  char version[128];
  char server_name[128];
  int log_level;
  char log_path[512];
  char root_path[512];
  int disable_args;
  int disable_type;
  int disable_zoom_up;
  int quality;
  char format[16];
  int mode;
  int save_new;
  int etag;
  int script_on;
  char script_name[512];
  char ssdb_ip[128];
  int ssdb_port;
  char img_path[512];
  char doc_path[512];
  char mov_path[512];
  int cache_on;
  char cache_ip[128];
  int cache_port;
  int max_size_img;
  int max_size_doc;
  int max_size_mov;
  ox_cbs_headers_conf_t *headers;
  ox_access_conf_t *up_access;
  ox_access_conf_t *down_access;
  multipart_parser_settings *mp_set;
  int (*get_img)(ox_req_t *, evhtp_request_t *);
};

extern ox_vars_t vars;
pthread_key_t thread_key;

#define LOG_FATAL       0           /* System is unusable */
#define LOG_ALERT       1           /* Action must be taken immediately */
#define LOG_CRIT        2           /* Critical conditions */
#define LOG_ERROR       3           /* Error conditions */
#define LOG_WARNING     4           /* Warning conditions */
#define LOG_NOTICE      5           /* Normal, but significant */
#define LOG_INFO        6           /* Information */
#define LOG_DEBUG       7           /* DEBUG message */

#ifdef DEBUG
#define LOG_PRINT(level, fmt, ...)                      \
  do {                                                  \
    int log_id = ox_log_open(vars.log_path, "a");          \
    ox_log_printf0(log_id, level, "%s:%d %s() "fmt,        \
                   __FILE__, __LINE__, __FUNCTION__,       \
                   ##__VA_ARGS__);                         \
    ox_log_close(log_id);                                     \
  } while (0)
#else
#define LOG_PRINT(level, fmt, ...)                                      \
  do {                                                                  \
    if (level <= vars.log_level) {                                      \
      int log_id = ox_log_open(vars.log_path, "a");                        \
      ox_log_printf0(log_id, level, fmt, ##__VA_ARGS__) ;                  \
      ox_log_close(log_id);                                                \
    }                                                                   \
  } while (0)
#endif

#endif
