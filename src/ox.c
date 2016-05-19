#include "ox.h"

ox_vars_t vars;

extern const struct luaL_reg ox_lib[];
extern const struct luaL_Reg loglib[];

static void vars_init(void)
{
  vars.is_daemon = 0;
  ox_strlcpy(vars.ip, "0.0.0.0", sizeof(vars.ip));
  vars.port = 9527;
  vars.num_threads = 2;         /* N workers */
  vars.backlog = 1024;
  vars.max_keepalives = 1;
  snprintf(vars.server_name, 128, "OX image server/v%s", vars.version);
  vars.log_level = 7;
  ox_strlcpy(vars.version, OX_VERSION, sizeof(vars.version));
  ox_strlcpy(vars.log_path, "./ox.log", sizeof(vars.log_path));
  ox_strlcpy(vars.img_path, "./img", sizeof(vars.img_path));
  ox_strlcpy(vars.doc_path, "./doc", sizeof(vars.doc_path));
  ox_strlcpy(vars.mov_path, "./mov", sizeof(vars.mov_path));
  ox_strlcpy(vars.format, "none", sizeof(vars.format));
  ox_strlcpy(vars.cache_ip, "127.0.0.1", sizeof(vars.cache_ip));
  ox_strlcpy(vars.root_path, "./index.html", sizeof(vars.root_path));
  ox_strlcpy(vars.ssdb_ip, "127.0.0.1", sizeof(vars.ssdb_ip));
  vars.ssdb_port = 6379;
  vars.mode = 1;
  vars.save_new = 1;
  vars.etag = 0;
  vars.cache_on = 0;
  vars.cache_port = 11211;
  vars.max_size_img = 10485760;
  vars.max_size_doc = 10485760;
  vars.max_size_mov = 10485760;
  vars.script_on = 0;
  vars.script_name[0] = '\0';
  vars.disable_args = 0;
  vars.disable_type = 0;
  vars.disable_zoom_up = 0;
  vars.headers = NULL;
  vars.quality = 75;
  vars.up_access = NULL;
  vars.down_access = NULL;

  multipart_parser_settings *callbacks = (multipart_parser_settings *)malloc(sizeof(multipart_parser_settings));
  memset(callbacks, 0, sizeof(multipart_parser_settings));
  //callbacks->on_header_field = on_header_field;
  callbacks->on_header_value = ox_cbs_on_header_value;
  callbacks->on_chunk_data = ox_cbs_on_chunk_data;
  vars.mp_set = callbacks;
}

static void set_callback(int mode)
{
  if(mode == 1) {
    vars.get_img = ox_img_get;
    vars.get_doc = ox_doc_get;
    vars.get_mov = ox_mov_get;
  }
  else {
    vars.get_img = ox_img_get_db;
    vars.get_doc = ox_doc_get_db;
    vars.get_mov = ox_mov_get_db;
  }
}

static int load_conf(const char *conf)
{
  lua_State *L = luaL_newstate();
  luaL_openlibs(L);
  if (luaL_loadfile(L, conf) || lua_pcall(L, 0, 0, 0)) {
    lua_close(L);
    return -1;
  }

  lua_getglobal(L, "is_daemon"); //stack index: -12
  if(lua_isnumber(L, -1)) {
    vars.is_daemon = (int)lua_tonumber(L, -1);
  }
  lua_pop(L, 1);

  lua_getglobal(L, "ip");
  if(lua_isstring(L, -1)) {
    ox_strlcpy(vars.ip, lua_tostring(L, -1), sizeof(vars.ip));
  }
  lua_pop(L, 1);

  lua_getglobal(L, "port");
  if(lua_isnumber(L, -1)) {
    vars.port = (int)lua_tonumber(L, -1);
  }
  lua_pop(L, 1);

  lua_getglobal(L, "thread_num");
  if(lua_isnumber(L, -1)) {
    vars.num_threads = (int)lua_tonumber(L, -1);         /* N workers */
  }
  lua_pop(L, 1);

  lua_getglobal(L, "backlog_num");
  if(lua_isnumber(L, -1)) {
    vars.backlog = (int)lua_tonumber(L, -1);
  }
  lua_pop(L, 1);

  lua_getglobal(L, "max_keepalives");
  if(lua_isnumber(L, -1)) {
    vars.max_keepalives = (int)lua_tonumber(L, -1);
  }
  lua_pop(L, 1);

  /* lua_getglobal(L, "retry"); */
  /* if(lua_isnumber(L, -1)) { */
  /*   vars.retry = (int)lua_tonumber(L, -1); */
  /* } */
  /* lua_pop(L, 1); */

  lua_getglobal(L, "system");
  if(lua_isstring(L, -1)) {
    char tmp[128];
    snprintf(tmp, 128, "%s %s", vars.server_name, lua_tostring(L, -1));
    snprintf(vars.server_name, 128, "%s", tmp);
  }
  lua_pop(L, 1);

  lua_getglobal(L, "headers");
  if(lua_isstring(L, -1)) {
    vars.headers = ox_cbs_get_headers_conf(lua_tostring(L, -1));
  }
  lua_pop(L, 1);

  lua_getglobal(L, "etag");
  if(lua_isnumber(L, -1)) {
    vars.etag = (int)lua_tonumber(L, -1);
  }
  lua_pop(L, 1);

  lua_getglobal(L, "upload_rule");
  if(lua_isstring(L, -1)) {
    vars.up_access = ox_access_get(lua_tostring(L, -1));
  }
  lua_pop(L, 1);

  lua_getglobal(L, "download_rule");
  if(lua_isstring(L, -1)) {
    vars.down_access = ox_access_get(lua_tostring(L, -1));
  }
  lua_pop(L, 1);

  lua_getglobal(L, "cache");
  if(lua_isnumber(L, -1)) {
    vars.cache_on = (int)lua_tonumber(L, -1);
  }
  lua_pop(L, 1);

  lua_getglobal(L, "memc_ip");
  if(lua_isstring(L, -1)) {
    ox_strlcpy(vars.cache_ip, lua_tostring(L, -1), sizeof(vars.cache_ip));
  }
  lua_pop(L, 1);

  lua_getglobal(L, "memc_port");
  if(lua_isnumber(L, -1)) {
    vars.cache_port = (int)lua_tonumber(L, -1);
  }
  lua_pop(L, 1);

  lua_getglobal(L, "log_level");
  if(lua_isnumber(L, -1)) {
    vars.log_level = (int)lua_tonumber(L, -1);
  }
  lua_pop(L, 1);

  lua_getglobal(L, "log_path"); //stack index: -1
  if(lua_isstring(L, -1)) {
    ox_strlcpy(vars.log_path, lua_tostring(L, -1), sizeof(vars.log_path));
  }
  lua_pop(L, 1);

  lua_getglobal(L, "root_path");
  if(lua_isstring(L, -1)) {
    ox_strlcpy(vars.root_path, lua_tostring(L, -1), sizeof(vars.root_path));
  }
  lua_pop(L, 1);

  lua_getglobal(L, "disable_args");
  if(lua_isnumber(L, -1)) {
    vars.disable_args = (int)lua_tonumber(L, -1);
  }
  lua_pop(L, 1);

  lua_getglobal(L, "disable_type");
  if(lua_isnumber(L, -1)) {
    vars.disable_type = (int)lua_tonumber(L, -1);
  }
  lua_pop(L, 1);

  lua_getglobal(L, "disable_zoom_up");
  if(lua_isnumber(L, -1)) {
    vars.disable_zoom_up = (int)lua_tonumber(L, -1);
  }
  lua_pop(L, 1);

  lua_getglobal(L, "script_name"); //stack index: -1
  if(lua_isstring(L, -1)) {
    ox_strlcpy(vars.script_name, lua_tostring(L, -1), sizeof(vars.script_name));
  }
  lua_pop(L, 1);

  lua_getglobal(L, "format");
  if(lua_isstring(L, -1)) {
    ox_strlcpy(vars.format, lua_tostring(L, -1), sizeof(vars.format));
  }
  lua_pop(L, 1);

  lua_getglobal(L, "quality");
  if(lua_isnumber(L, -1)) {
    vars.quality = (int)lua_tonumber(L, -1);
  }
  lua_pop(L, 1);

  lua_getglobal(L, "mode");
  if(lua_isnumber(L, -1)) {
    vars.mode = (int)lua_tonumber(L, -1);
  }
  lua_pop(L, 1);

  set_callback(vars.mode);

  lua_getglobal(L, "save_new");
  if(lua_isnumber(L, -1)) {
    vars.save_new = (int)lua_tonumber(L, -1);
  }
  lua_pop(L, 1);

  lua_getglobal(L, "max_size_img");
  if(lua_isnumber(L, -1)) {
    vars.max_size_img = (int)lua_tonumber(L, -1);
  }
  lua_pop(L, 1);

  lua_getglobal(L, "max_size_doc");
  if(lua_isnumber(L, -1)) {
    vars.max_size_doc = (int)lua_tonumber(L, -1);
  }
  lua_pop(L, 1);

  lua_getglobal(L, "max_size_mov");
  if(lua_isnumber(L, -1)) {
    vars.max_size_mov = (int)lua_tonumber(L, -1);
  }
  lua_pop(L, 1);

  lua_getglobal(L, "img_path");
  if(lua_isstring(L, -1)) {
    ox_strlcpy(vars.img_path, lua_tostring(L, -1), sizeof(vars.img_path));
  }
  lua_pop(L, 1);

  lua_getglobal(L, "doc_path");
  if(lua_isstring(L, -1)) {
    ox_strlcpy(vars.doc_path, lua_tostring(L, -1), sizeof(vars.doc_path));
  }
  lua_pop(L, 1);

  lua_getglobal(L, "mov_path");
  if(lua_isstring(L, -1)) {
    ox_strlcpy(vars.mov_path, lua_tostring(L, -1), sizeof(vars.mov_path));
  }
  lua_pop(L, 1);

  lua_getglobal(L, "ssdb_ip");
  if(lua_isstring(L, -1)) {
    ox_strlcpy(vars.ssdb_ip, lua_tostring(L, -1), sizeof(vars.ssdb_ip));
  }
  lua_pop(L, 1);

  lua_getglobal(L, "ssdb_port");
  if(lua_isnumber(L, -1)) {
    vars.ssdb_port = (int)lua_tonumber(L, -1);
  }
  lua_pop(L, 1);

  vars.L = L;
  //lua_close(L);

  return 1;
}

void init_thread(evhtp_t *htp, evthr_t *thread, void *arg)
{
  thr_arg_t *thr_args;
  thr_args = calloc(1, sizeof(thr_arg_t));
  LOG_PRINT(LOG_DEBUG, "thr_args alloc");
  thr_args->thread = thread;

  char mserver[32];

  if(vars.cache_on == true) {
    memcached_st *memc = memcached_create(NULL);
    snprintf(mserver, 32, "%s:%d", vars.cache_ip, vars.cache_port);
    memcached_server_st *servers = memcached_servers_parse(mserver);
    memcached_server_push(memc, servers);
    memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL, 1);
    memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_NO_BLOCK, 1);
    memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_NOREPLY, 1);
    memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_TCP_KEEPALIVE, 1);
    thr_args->cache_conn = memc;
    LOG_PRINT(LOG_DEBUG, "Memcached Connection Init Finished.");
    memcached_server_list_free(servers);
  }
  else {
    thr_args->cache_conn = NULL;
  }

  thr_args->ssdb_conn = NULL;
  if(vars.mode == 3) {
    redisContext* c = redisConnect(vars.ssdb_ip, vars.ssdb_port);
    if(c->err) {
      redisFree(c);
      LOG_PRINT(LOG_DEBUG, "Connect to ssdb server faile");
    }
    else {
      thr_args->ssdb_conn = c;
      LOG_PRINT(LOG_DEBUG, "Connect to ssdb server Success");
    }
  }

  thr_args->L = luaL_newstate();
  LOG_PRINT(LOG_DEBUG, "luaL_newstate alloc");
  if(thr_args->L != NULL) {
    luaL_openlibs(thr_args->L);
    luaL_openlib(thr_args->L, "ox", ox_lib, 0);
    luaL_openlib(thr_args->L, "log", loglib, 0);
  }
  luaL_loadfile(thr_args->L, vars.script_name);
  lua_pcall(thr_args->L, 0, 0, 0);

  evthr_set_aux(thread, thr_args);
}

int main()
{
  vars_init();
  const char *conf_file = "ox.lua";
  if(load_conf(conf_file) == -1) {
    fprintf(stderr, "'%s' load failed!\n", conf_file);
    return -1;
  }

  if(vars.is_daemon == 1) {
    if(daemon(1, 1) < 0) {
      fprintf(stderr, "Create daemon failed!\n");
      return -1;
    }
    else {
      fprintf(stdout, "ox %s\n", vars.version);
      fprintf(stdout, "Copyright (c) 2015-2016 l.inux.xyz\n");
      fprintf(stderr, "\n");
    }
  }

  if(ox_mkdirf(vars.log_path) != 1) {
    fprintf(stderr, "%s log path create failed!\n", vars.log_path);
    return -1;
  }
  ox_log_init();

  if(vars.script_name[0] != '\0') {
    if(ox_isfile(vars.script_name) == -1) {
      fprintf(stderr, "%s open failed!\n", vars.script_name);
      return -1;
    }
    vars.script_on = 1;
  }

  if(ox_isdir(vars.img_path) != 1) {
    if(ox_mkdirs(vars.img_path) != 1) {
      LOG_PRINT(LOG_DEBUG, "img_path[%s] Create Failed!", vars.img_path);
      fprintf(stderr, "%s Create Failed!\n", vars.img_path);
      return -1;
    }
  }
  LOG_PRINT(LOG_DEBUG,"Paths Init Finished.");

  if(vars.mode == 3) {
    redisContext* c = redisConnect(vars.ssdb_ip, vars.ssdb_port);
    if(c->err) {
      redisFree(c);
      LOG_PRINT(LOG_DEBUG, "Connect to ssdb server faile");
      fprintf(stderr, "SSDB[%s:%d] Connect Failed!\n", vars.ssdb_ip, vars.ssdb_port);
      return -1;
    }
    else {
      LOG_PRINT(LOG_DEBUG, "Connect to ssdb server Success");
    }
  }

  /* //init magickwand */
  /* MagickCoreGenesis((char *) NULL, MagickFalse); */

  //begin to start httpd...
  LOG_PRINT(LOG_DEBUG, "Begin to Start Httpd Server...");
  LOG_PRINT(LOG_INFO, "ox started");

  // httpd
  evbase_t *evbase = event_base_new();
  evhtp_t *htp = evhtp_new(evbase, NULL);

  // index
  evhtp_set_cb(htp, "/index", ox_cbs_index, NULL);

  // image
  evhtp_set_cb(htp, "/img/", ox_cbs_img, NULL);
  evhtp_set_cb(htp, "/img", ox_cbs_img, NULL);

  // doc
  evhtp_set_cb(htp, "/doc/", ox_cbs_doc, NULL);
  evhtp_set_cb(htp, "/doc", ox_cbs_doc, NULL);

  // video
  evhtp_set_cb(htp, "/mov/", ox_cbs_mov, NULL);
  evhtp_set_cb(htp, "/mov", ox_cbs_mov, NULL);

  // all other
  evhtp_set_gencb(htp, ox_cbs_index, NULL);

#ifndef EVHTP_DISABLE_EVTHR
  evhtp_use_threads_wexit(htp, init_thread, NULL, vars.num_threads, NULL);
  //evhtp_use_threads_wexit(htp, NULL, NULL, vars.num_threads, NULL);
#endif

  evhtp_set_max_keepalive_requests(htp, vars.max_keepalives);
  evhtp_bind_socket(htp, vars.ip, vars.port, vars.backlog);

  event_base_loop(evbase, 0);

  evhtp_unbind_socket(htp);
  evhtp_free(htp);
  event_base_free(evbase);
  ox_cbs_headers_free(vars.headers);
  ox_access_free(vars.up_access);
  ox_access_free(vars.down_access);
  free(vars.mp_set);

  return 0;
}
