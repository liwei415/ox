#include "ox_cbs_doc.h"

static const char *method_strmap[] = {
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "DELETE",
  "MKCOL",
  "COPY",
  "MOVE",
  "OPTIONS",
  "PROPFIND",
  "PROPATCH",
  "LOCK",
  "UNLOCK",
  "TRACE",
  "CONNECT",
  "PATCH",
  "UNKNOWN",
};

int _binary_parse_doc(evhtp_request_t *req, const char *content_type, const char *address, const char *buff, int post_size)
{
  int err_no = 0;

  // libmagic 检测文件头
  magic_t magic_cookie;
  magic_cookie = magic_open(MAGIC_MIME_TYPE);
  if (magic_cookie == NULL) {
    goto done;
  }
  magic_load(magic_cookie, NULL);

  //做错误标记err_no = 1
  const char *ctype = magic_buffer(magic_cookie, buff, post_size);
  if (ox_isdoc(ctype) != 1) {
    err_no = 1;
  }
  magic_close(magic_cookie);

  if (err_no == 1) {
    LOG_PRINT(LOG_DEBUG, "fileType[%s] is Not Supported!", ctype);
    LOG_PRINT(LOG_ERROR, "%s fail post type", address);
    goto done;
  }

  char md5sum[33];
  LOG_PRINT(LOG_DEBUG, "Begin to save doc...");
  evthr_t *thread = ox_cbs_get_request_thr(req);
  thr_arg_t *thr_arg = (thr_arg_t *)evthr_get_aux(thread);
  if(ox_doc_save(thr_arg, buff, post_size, md5sum) == -1) {
    LOG_PRINT(LOG_DEBUG, "Doc save failed!");
    LOG_PRINT(LOG_ERROR, "%s fail post save", address);
    goto done;
  }

  err_no = -1;
  LOG_PRINT(LOG_INFO, "%s succ post pic:%s size:%d", address, md5sum, post_size);
  ox_cbs_jreturn(req, err_no, md5sum, post_size);

done:
    return err_no;
}

void ox_cbs_docs_post(evhtp_request_t *req, void *arg)
{
  int post_size = 0;
  char *buff = NULL;
  int err_no = 0;
  int ret_json = 1;

  evhtp_connection_t *ev_conn = evhtp_request_get_connection(req);
  struct sockaddr *saddr = ev_conn->saddr;
  struct sockaddr_in *ss = (struct sockaddr_in *)saddr;
  char address[16];

  // 过滤method
  int req_method = evhtp_request_get_method(req);
  if(req_method >= 16) {
    req_method = 16;
  }

  LOG_PRINT(LOG_DEBUG, "Method: %d", req_method);
  if(strcmp(method_strmap[req_method], "POST") != 0) {
    LOG_PRINT(LOG_DEBUG, "Request Method Not Support.");
    goto err;
  }

  // 此处无法获得ip，处理办法：反相代理里面设置或者haproxy设置或者iptables，或者ip过滤放在外部，或者等我有空再改
  const char *xff_address = evhtp_header_find(req->headers_in, "X-Forwarded-For");
  if (xff_address) {
    inet_aton(xff_address, &ss->sin_addr);
  }
  else {
    inet_aton("0.0.0.0", &ss->sin_addr);
  }
  strncpy(address, inet_ntoa(ss->sin_addr), 16);

  if (vars.up_access != NULL) {
    int acs = ox_access_inet(vars.up_access, ss->sin_addr.s_addr);
    LOG_PRINT(LOG_DEBUG, "access check: %d", acs);
    if(acs == OX_FORBIDDEN) {
      LOG_PRINT(LOG_DEBUG, "check access: ip[%s] forbidden!", address);
      LOG_PRINT(LOG_INFO, "%s refuse post forbidden", address);
      err_no = 3;
      goto forbidden;
    }
    else if (acs == OX_ERROR) {
      LOG_PRINT(LOG_DEBUG, "check access: check ip[%s] failed!", address);
      LOG_PRINT(LOG_ERROR, "%s fail post access %s", address);
      err_no = 0;
      goto err;
    }
  }

  const char *content_len = evhtp_header_find(req->headers_in, "Content-Length");
  if(!content_len) {
    LOG_PRINT(LOG_DEBUG, "Get Content-Length error!");
    LOG_PRINT(LOG_ERROR, "%s fail post content-length", address);
    err_no = 5;
    goto err;
  }
  post_size = atoi(content_len);
  if(post_size <= 0) {
    LOG_PRINT(LOG_DEBUG, "Doc size is zero!");
    LOG_PRINT(LOG_ERROR, "%s fail post empty", address);
    err_no = 5;
    goto err;
  }
  if(post_size > vars.max_size_doc) {
    LOG_PRINT(LOG_DEBUG, "Doc size too large!");
    LOG_PRINT(LOG_ERROR, "%s fail post large", address);
    err_no = 7;
    goto err;
  }
  const char *content_type = evhtp_header_find(req->headers_in, "Content-Type");
  if(!content_type) {
    LOG_PRINT(LOG_DEBUG, "Get Content-Type error!");
    LOG_PRINT(LOG_ERROR, "%s fail post content-type", address);
    err_no = 6;
    goto err;
  }
  evbuf_t *buf;
  buf = req->buffer_in;
  buff = (char *)calloc(post_size + 1, sizeof(char));
  if(buff == NULL) {
    LOG_PRINT(LOG_DEBUG, "buff malloc failed!");
    LOG_PRINT(LOG_ERROR, "%s fail malloc buff", address);
    err_no = 0;
    goto err;
  }
  int rmblen, evblen;
  if(evbuffer_get_length(buf) <= 0) {
    LOG_PRINT(LOG_DEBUG, "Empty Request!");
    LOG_PRINT(LOG_ERROR, "%s fail post empty", address);
    err_no = 4;
    goto err;
  }
  while((evblen = evbuffer_get_length(buf)) > 0) {
    LOG_PRINT(LOG_DEBUG, "evblen = %d", evblen);
    rmblen = evbuffer_remove(buf, buff, evblen);
    LOG_PRINT(LOG_DEBUG, "rmblen = %d", rmblen);
    if(rmblen < 0) {
      LOG_PRINT(LOG_DEBUG, "evbuffer_remove failed!");
      LOG_PRINT(LOG_ERROR, "%s fail post parse", address);
      err_no = 4;
      goto err;
    }
  }

  if(strstr(content_type, "multipart/form-data") == NULL) {
    err_no = _binary_parse_doc(req, content_type, address, buff, post_size);
  }
  else {
    ret_json = 0;
    err_no = ox_cbs_multipart_parse(req, content_type, address, buff, post_size);
  }
  if(err_no != -1) {
    goto err;
  }
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============ox_cbs_post() DONE!===============");
  goto done;

 forbidden:
  ox_cbs_jreturn(req, err_no, NULL, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============post_request_cb() FORBIDDEN!===============");
  goto done;

 err:
  if(ret_json == 0) {
    evbuffer_add_printf(req->buffer_out, "<h1>Upload Failed!</h1></body></html>");
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
  }
  else {
    ox_cbs_jreturn(req, err_no, NULL, 0);
  }
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============ox_cbs_post() ERROR!===============");

 done:
  free(buff);
}

void ox_cbs_doc_get(evhtp_request_t *req, void *arg)
{
  char *md5 = NULL;
  char *fmt = NULL;
  char *type = NULL;
  char *passwd = NULL;
  char *buff = NULL;
  char *fname = NULL;
  size_t len;
  int acs = -9;
  ox_req_doc_t *ox_req = NULL;

  evhtp_connection_t *ev_conn = evhtp_request_get_connection(req);
  struct sockaddr *saddr = ev_conn->saddr;
  struct sockaddr_in *ss = (struct sockaddr_in *)saddr;
  char address[16];

  int req_method = evhtp_request_get_method(req);
  if(req_method >= 16) {
    req_method = 16;
  }

  LOG_PRINT(LOG_DEBUG, "Method: %d", req_method);
  if(strcmp(method_strmap[req_method], "GET") != 0) {
    LOG_PRINT(LOG_DEBUG, "Request Method Not Support.");
    goto err;
  }

  const char *xff_address = evhtp_header_find(req->headers_in, "X-Forwarded-For");
  if(xff_address) {
    inet_aton(xff_address, &ss->sin_addr);
  }
  else {
    inet_aton("0.0.0.0", &ss->sin_addr);
  }
  strncpy(address, inet_ntoa(ss->sin_addr), 16);

  if(vars.down_access != NULL) {
    acs = ox_access_inet(vars.down_access, ss->sin_addr.s_addr);
    LOG_PRINT(LOG_DEBUG, "access check: %d", acs);
  }

  // 获得uri并解析
  const char *uri = req->uri->path->full;
  if((strlen(uri) == 4 || strlen(uri) == 5) &&
     uri[0]=='/' && uri[1]=='d' && uri[2]=='o' && uri[3]=='c') {
    LOG_PRINT(LOG_DEBUG, "Root Request.");
    int fd = -1;
    struct stat st;
    if((fd = open(vars.root_path, O_RDONLY)) == -1) {
      LOG_PRINT(LOG_DEBUG, "Root_page Open Failed. Return Default Page.");
      evbuffer_add_printf(req->buffer_out, "<html><body><h1>doc get: no key</h1></body></html>");
    }
    else {
      if (fstat(fd, &st) < 0) {
        /* Make sure the length still matches, now that we
         * opened the file :/ */
        LOG_PRINT(LOG_DEBUG, "Root_page Length fstat Failed. Return Default Page.");
        evbuffer_add_printf(req->buffer_out, "<html><body><h1>doc get: no key</h1></body></html>");
      }
      else {
        evbuffer_add_file(req->buffer_out, fd, 0, st.st_size);
      }
    }
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
    evhtp_send_reply(req, EVHTP_RES_OK);
    LOG_PRINT(LOG_DEBUG, "============_doc_get() DONE!===============");
    LOG_PRINT(LOG_INFO, "%s succ root page", address);
    goto done;
  }

  if(strstr(uri, "favicon.ico")) {
    LOG_PRINT(LOG_DEBUG, "favicon.ico Request, Denied.");
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
    ox_cbs_headers_add(req, vars.headers);
    evhtp_send_reply(req, EVHTP_RES_OK);
    goto done;
  }
  LOG_PRINT(LOG_DEBUG, "Got a GET request for <%s>",  uri);

  /* Don't allow any ".."s in the path, to avoid exposing stuff outside */
  /* of the docroot.  This test is both overzealous and underzealous: */
  /* it forbids aceptable paths like "/this/one..here", but it doesn't */
  /* do anything to prevent symlink following." */
  if (strstr(uri, "..")) {
    LOG_PRINT(LOG_DEBUG, "attempt to upper dir!");
    LOG_PRINT(LOG_INFO, "%s refuse directory", address);
    goto forbidden;
  }

  size_t md5_len = strlen(uri) + 1;
  md5 = (char *)malloc(md5_len);
  if(md5 == NULL) {
    LOG_PRINT(LOG_DEBUG, "md5 malloc failed!");
    LOG_PRINT(LOG_ERROR, "%s fail malloc", address);
    goto err;
  }
  if(uri[0] == '/'){
    ox_strlcpy(md5, uri+1+3+1, md5_len);//这里处理URL
  }
  else {
    ox_strlcpy(md5, uri, md5_len);
  }
  LOG_PRINT(LOG_DEBUG, "md5 of request is <%s>",  md5);
  if(ox_ismd5(md5) == -1) {
    LOG_PRINT(LOG_DEBUG, "Url is Not a OX Request.");
    LOG_PRINT(LOG_INFO, "%s refuse url illegal", address);
    goto err;
  }

  evthr_t *thread = ox_cbs_get_request_thr(req);
  thr_arg_t *thr_arg = (thr_arg_t *)evthr_get_aux(thread);

  // 如果请求带有文件名，则返回文件名，否则不返回
  evhtp_kvs_t *params;
  params = req->uri->query;
  if(params != NULL) {
    const char *str_n = evhtp_kv_find(params, "n");
    LOG_PRINT(LOG_DEBUG, "fname = %s", str_n);
    if(str_n) {
      size_t nlen = strlen(str_n) + 21 + 1 + 1;
      fname = (char *)calloc(nlen, sizeof(char)+1);
      if(fname != NULL) {
        snprintf(fname, nlen - 1, "attachment; filename=%s", str_n);
      }
      LOG_PRINT(LOG_DEBUG, "fname = %s", fname);
    }

    const char *str_p = evhtp_kv_find(params, "p");
    if(str_p) {
      size_t p_len = strlen(str_p) + 1;
      passwd = (char *)malloc(p_len);
      if(passwd != NULL) {
        ox_strlcpy(passwd, str_p, p_len);
      }
      LOG_PRINT(LOG_DEBUG, "passwd = %s", passwd);
    }
  }

  ox_req = (ox_req_doc_t *)calloc(1, sizeof(ox_req_doc_t));
  ox_req->md5 = md5;
  ox_req->thr_arg = thr_arg;
  ox_req->fname = fname;

  int get_doc_rst = -1;

  // storage setting
  if (vars.mode == 1) {
    get_doc_rst = ox_doc_get(ox_req, req);
  }
  else {
    get_doc_rst = ox_doc_get_db(ox_req, req);
  }

  if(get_doc_rst == -1) {
    LOG_PRINT(LOG_DEBUG, "OX Requset Get Doc[MD5: %s] Failed!", md5);
    goto err;
  }

  //加锁无权限
  if(get_doc_rst == -2) {
    LOG_PRINT(LOG_DEBUG, "Doc [MD5: %s] locked!", ox_req->md5);
    goto err;
  }

  len = evbuffer_get_length(req->buffer_out);
  LOG_PRINT(LOG_DEBUG, "get buffer length: %d", len);

  LOG_PRINT(LOG_DEBUG, "Got the File!");
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  //todo libmagic处理mime
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "application/octet-stream", 0, 0));
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Disposition", fname, 0, 0));

  ox_cbs_headers_add(req, vars.headers);
  evhtp_send_reply(req, EVHTP_RES_OK);

  LOG_PRINT(LOG_DEBUG, "============ox_cbs_get() DONE!===============");
  goto done;

 forbidden:
  evbuffer_add_printf(req->buffer_out, "<html><body><h1>403 Forbidden!</h1></body></html>");
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
  evhtp_send_reply(req, EVHTP_RES_FORBIDDEN);
  LOG_PRINT(LOG_DEBUG, "============ox_cbs_get() FORBIDDEN!===============");
  goto done;

 err:
  evbuffer_add_printf(req->buffer_out, "<html><body><h1>404 Not Found!</h1></body></html>");
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
  evhtp_send_reply(req, EVHTP_RES_NOTFOUND);
  LOG_PRINT(LOG_DEBUG, "============ox_cbs_get() ERROR!===============");

 done:
  free(fmt);
  free(md5);
  free(type);
  free(passwd);
  free(buff);
  free(fname);
  free(ox_req);
}

void ox_cbs_doc_del(evhtp_request_t *req, void *arg)
{
  char md5[35];
  int err_no = 0;

  ox_req_doc_t *ox_req = NULL;

  evhtp_connection_t *ev_conn = evhtp_request_get_connection(req);
  struct sockaddr *saddr = ev_conn->saddr;
  struct sockaddr_in *ss = (struct sockaddr_in *)saddr;
  char address[16];

  int req_method = evhtp_request_get_method(req);
  if(req_method >= 16) {
    req_method = 16;
  }

  LOG_PRINT(LOG_DEBUG, "Method: %d", req_method);
  if(strcmp(method_strmap[req_method], "GET") != 0) {
    LOG_PRINT(LOG_DEBUG, "Request Method Not Support.");
    err_no = 2;
    goto err;
  }

  const char *xff_address = evhtp_header_find(req->headers_in, "X-Forwarded-For");
  if(xff_address) {
    inet_aton(xff_address, &ss->sin_addr);
  }
  else {
    inet_aton("0.0.0.0", &ss->sin_addr);
  }
  strncpy(address, inet_ntoa(ss->sin_addr), 16);

  if (vars.up_access != NULL) {
    int acs = ox_access_inet(vars.up_access, ss->sin_addr.s_addr);
    LOG_PRINT(LOG_DEBUG, "access check: %d", acs);
    if(acs == OX_FORBIDDEN) {
      LOG_PRINT(LOG_DEBUG, "check access: ip[%s] forbidden!", address);
      LOG_PRINT(LOG_INFO, "%s refuse post forbidden", address);
      err_no = 3;
      goto forbidden;
    }
    else if (acs == OX_ERROR) {
      LOG_PRINT(LOG_DEBUG, "check access: check ip[%s] failed!", address);
      LOG_PRINT(LOG_ERROR, "%s fail post access %s", address);
      err_no = 0;
      goto err;
    }
  }

  // 获得uri并解析
  const char *uri = req->uri->path->full;
  if((strlen(uri) == 5 || strlen(uri) == 6) &&
     uri[0]=='/' && uri[1]=='d' && uri[2]=='o' && uri[3]=='c' &&
     uri[4]=='/' && uri[5]=='d' && uri[6]=='e' && uri[7]=='l' && uri[8]=='/') {
    LOG_PRINT(LOG_DEBUG, "Root Request.");
    int fd = -1;
    struct stat st;
    if((fd = open(vars.root_path, O_RDONLY)) == -1) {
      LOG_PRINT(LOG_DEBUG, "Root_page Open Failed. Return Default Page.");
      err_no =3;
      goto err;
    }
    else {
      if (fstat(fd, &st) < 0) {
        /* Make sure the length still matches, now that we
         * opened the file :/ */
        LOG_PRINT(LOG_DEBUG, "Root_page Length fstat Failed. Return Default Page.");
        err_no =3;
        goto err;
      }
      else {
        evbuffer_add_file(req->buffer_out, fd, 0, st.st_size);
      }
    }
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
    evhtp_send_reply(req, EVHTP_RES_OK);
    LOG_PRINT(LOG_DEBUG, "============_doc_del() DONE!===============");
    LOG_PRINT(LOG_INFO, "%s succ root page", address);
    goto done;
  }

  if(strstr(uri, "favicon.ico")) {
    LOG_PRINT(LOG_DEBUG, "favicon.ico Request, Denied.");
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
    ox_cbs_headers_add(req, vars.headers);
    evhtp_send_reply(req, EVHTP_RES_OK);
    goto done;
  }
  LOG_PRINT(LOG_DEBUG, "Got a GET request for <%s>",  uri);

  /* Don't allow any ".."s in the path, to avoid exposing stuff outside */
  /* of the docroot.  This test is both overzealous and underzealous: */
  /* it forbids aceptable paths like "/this/one..here", but it doesn't */
  /* do anything to prevent symlink following." */
  if (strstr(uri, "..")) {
    LOG_PRINT(LOG_DEBUG, "attempt to upper dir!");
    LOG_PRINT(LOG_INFO, "%s refuse directory", address);
    err_no = 3;
    goto forbidden;
  }

  ox_strlcpy(md5, uri+1+7+1, 33);//这里处理URL
  if(ox_ismd5(md5) == -1) {
    LOG_PRINT(LOG_DEBUG, "Url [%s] is Not a OX Request.", md5);
    LOG_PRINT(LOG_INFO, "%s refuse url illegal", address);
    err_no = 8;
    goto err;
  }

  evthr_t *thread = ox_cbs_get_request_thr(req);
  thr_arg_t *thr_arg = (thr_arg_t *)evthr_get_aux(thread);

  ox_req = (ox_req_doc_t *)calloc(1, sizeof(ox_req_doc_t));
  ox_req->md5 = md5;
  ox_req->thr_arg = thr_arg;

  int del_doc_rst = -1;

  // storage setting
  if (vars.mode == 1) {
    del_doc_rst = ox_doc_del(ox_req, req);
  }
  else {
    del_doc_rst = ox_doc_del_db(ox_req, req);
  }

  if(del_doc_rst == 2) {
    LOG_PRINT(LOG_DEBUG, "Del doc[MD5: %s] failed, path is not exists!", md5);
    err_no = 10;
    goto err;
  }
  else {
    err_no = -1;
  }

  ox_cbs_jreturn(req, err_no, md5, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============_doc_del() DONE!===============");
  goto done;

 forbidden:
  ox_cbs_jreturn(req, err_no, NULL, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============_doc_del() FORBIDDEN!===============");
  goto done;

 err:
  ox_cbs_jreturn(req, err_no, NULL, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============_doc_del() ERROR!===============");

 done:
  free(ox_req);
}

void ox_cbs_docs_del(evhtp_request_t *req, void *arg)
{
  char md5[33];
  char *buff = NULL;
  int post_size = 0;
  int err_no = 0;

  ox_req_doc_t *ox_req = NULL;

  evhtp_connection_t *ev_conn = evhtp_request_get_connection(req);
  struct sockaddr *saddr = ev_conn->saddr;
  struct sockaddr_in *ss = (struct sockaddr_in *)saddr;
  char address[16];

  int req_method = evhtp_request_get_method(req);
  if(req_method >= 16) {
    req_method = 16;
  }

  LOG_PRINT(LOG_DEBUG, "Method: %d", req_method);
  if(strcmp(method_strmap[req_method], "POST") != 0) {
    LOG_PRINT(LOG_DEBUG, "Request Method Not Support.");
    err_no = 2;
    goto err;
  }

  const char *xff_address = evhtp_header_find(req->headers_in, "X-Forwarded-For");
  if(xff_address) {
    inet_aton(xff_address, &ss->sin_addr);
  }
  else {
    inet_aton("0.0.0.0", &ss->sin_addr);
  }
  strncpy(address, inet_ntoa(ss->sin_addr), 16);

  if (vars.up_access != NULL) {
    int acs = ox_access_inet(vars.up_access, ss->sin_addr.s_addr);
    LOG_PRINT(LOG_DEBUG, "access check: %d", acs);
    if(acs == OX_FORBIDDEN) {
      LOG_PRINT(LOG_DEBUG, "check access: ip[%s] forbidden!", address);
      LOG_PRINT(LOG_INFO, "%s refuse post forbidden", address);
      err_no = 3;
      goto forbidden;
    }
    else if (acs == OX_ERROR) {
      LOG_PRINT(LOG_DEBUG, "check access: check ip[%s] failed!", address);
      LOG_PRINT(LOG_ERROR, "%s fail post access %s", address);
      err_no = 0;
      goto err;
    }
  }

  const char *content_len = evhtp_header_find(req->headers_in, "Content-Length");
  if(!content_len) {
    LOG_PRINT(LOG_DEBUG, "Get Content-Length error!");
    LOG_PRINT(LOG_ERROR, "%s fail post content-length", address);
    err_no = 5;
    goto err;
  }
  post_size = atoi(content_len);
  if(post_size <= 0) {
    LOG_PRINT(LOG_DEBUG, "Doc Size is Zero!");
    LOG_PRINT(LOG_ERROR, "%s fail post empty", address);
    err_no = 5;
    goto err;
  }
  if(post_size > vars.max_size_doc) {
    LOG_PRINT(LOG_DEBUG, "Doc Size Too Large!");
    LOG_PRINT(LOG_ERROR, "%s fail post large", address);
    err_no = 7;
    goto err;
  }
  evbuf_t *buf;
  buf = req->buffer_in;
  buff = (char *)calloc(post_size + 1, sizeof(char));
  if(buff == NULL) {
    LOG_PRINT(LOG_DEBUG, "buff malloc failed!");
    LOG_PRINT(LOG_ERROR, "%s fail malloc buff", address);
    err_no = 0;
    goto err;
  }
  int rmblen, evblen;
  if(evbuffer_get_length(buf) <= 0) {
    LOG_PRINT(LOG_DEBUG, "Empty Request!");
    LOG_PRINT(LOG_ERROR, "%s fail post empty", address);
    err_no = 4;
    goto err;
  }
  while((evblen = evbuffer_get_length(buf)) > 0) {
    LOG_PRINT(LOG_DEBUG, "evblen = %d", evblen);
    rmblen = evbuffer_remove(buf, buff, evblen);
    LOG_PRINT(LOG_DEBUG, "rmblen = %d", rmblen);
    if(rmblen < 0) {
      LOG_PRINT(LOG_DEBUG, "evbuffer_remove failed!");
      LOG_PRINT(LOG_ERROR, "%s fail post parse", address);
      err_no = 4;
      goto err;
    }
  }

  evthr_t *thread = ox_cbs_get_request_thr(req);
  thr_arg_t *thr_arg = (thr_arg_t *)evthr_get_aux(thread);

  ox_req = (ox_req_doc_t *)calloc(1, sizeof(ox_req_doc_t));
  ox_req->md5 = md5;
  ox_req->thr_arg = thr_arg;

  cJSON *root, *sub, *chd;
  if((root = cJSON_Parse(buff)) == NULL) {
    err_no = 11;
    goto err;
  }

  int i, j_size = cJSON_GetArraySize(root);
  for (i = 0; i < j_size; i++) {
    sub = cJSON_GetArrayItem(root, i);
    chd = cJSON_GetObjectItem(sub, "md5");
    if (chd == NULL) {
      err_no = 12;
      goto jerr;
    }
    ox_strlcpy(ox_req->md5, chd->valuestring, 33);
    if (vars.mode == 1) {
      ox_doc_del(ox_req, req);
    }
    else {
      ox_doc_del_db(ox_req, req);
    }
  }
  err_no = -1;

  ox_cbs_jreturn(req, err_no, md5, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============_doc_del() DONE!===============");
  goto jdone;

 forbidden:
  ox_cbs_jreturn(req, err_no, NULL, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============_doc_del() FORBIDDEN!===============");
  goto done;

 jerr:
  cJSON_Delete(root);

 err:
  ox_cbs_jreturn(req, err_no, NULL, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============_doc_del() ERROR!===============");
  goto done;

 jdone:
  cJSON_Delete(root);

 done:
  free(buff);
  free(ox_req);
}

void ox_cbs_doc_lock(evhtp_request_t *req, void *arg)
{
  char md5[35];
  char *passwd = NULL;
  int err_no = 0;

  ox_req_lock_t *ox_req = NULL;

  evhtp_connection_t *ev_conn = evhtp_request_get_connection(req);
  struct sockaddr *saddr = ev_conn->saddr;
  struct sockaddr_in *ss = (struct sockaddr_in *)saddr;
  char address[16];

  int req_method = evhtp_request_get_method(req);
  if(req_method >= 16) {
    req_method = 16;
  }

  LOG_PRINT(LOG_DEBUG, "Method: %d", req_method);
  if(strcmp(method_strmap[req_method], "GET") != 0) {
    LOG_PRINT(LOG_DEBUG, "Request Method Not Support.");
    err_no = 2;
    goto err;
  }

  const char *xff_address = evhtp_header_find(req->headers_in, "X-Forwarded-For");
  if(xff_address) {
    inet_aton(xff_address, &ss->sin_addr);
  }
  else {
    inet_aton("0.0.0.0", &ss->sin_addr);
  }
  strncpy(address, inet_ntoa(ss->sin_addr), 16);

  if (vars.up_access != NULL) {
    int acs = ox_access_inet(vars.up_access, ss->sin_addr.s_addr);
    LOG_PRINT(LOG_DEBUG, "access check: %d", acs);
    if(acs == OX_FORBIDDEN) {
      LOG_PRINT(LOG_DEBUG, "check access: ip[%s] forbidden!", address);
      LOG_PRINT(LOG_INFO, "%s refuse post forbidden", address);
      err_no = 3;
      goto forbidden;
    }
    else if (acs == OX_ERROR) {
      LOG_PRINT(LOG_DEBUG, "check access: check ip[%s] failed!", address);
      LOG_PRINT(LOG_ERROR, "%s fail post access %s", address);
      err_no = 0;
      goto err;
    }
  }

  // 获得uri并解析
  const char *uri = req->uri->path->full;
  if((strlen(uri) == 5 || strlen(uri) == 6) &&
     uri[0]=='/' && uri[1]=='d' && uri[2]=='o' && uri[3]=='c' &&
     uri[4]=='/' && uri[5]=='l' && uri[6]=='o' && uri[7]=='c' && uri[8]=='k' && uri[9]=='/') {
    LOG_PRINT(LOG_DEBUG, "Root Request.");
    int fd = -1;
    struct stat st;
    if((fd = open(vars.root_path, O_RDONLY)) == -1) {
      LOG_PRINT(LOG_DEBUG, "Root_page Open Failed. Return Default Page.");
      err_no = 3;
      goto err;
    }
    else {
      if (fstat(fd, &st) < 0) {
        /* Make sure the length still matches, now that we
         * opened the file :/ */
        LOG_PRINT(LOG_DEBUG, "Root_page Length fstat Failed. Return Default Page.");
        err_no = 3;
        goto err;
      }
      else {
        evbuffer_add_file(req->buffer_out, fd, 0, st.st_size);
      }
    }
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
    evhtp_send_reply(req, EVHTP_RES_OK);
    LOG_PRINT(LOG_DEBUG, "============_doc_del() DONE!===============");
    LOG_PRINT(LOG_INFO, "%s succ root page", address);
    goto done;
  }

  if(strstr(uri, "favicon.ico")) {
    LOG_PRINT(LOG_DEBUG, "favicon.ico Request, Denied.");
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
    ox_cbs_headers_add(req, vars.headers);
    evhtp_send_reply(req, EVHTP_RES_OK);
    goto done;
  }
  LOG_PRINT(LOG_DEBUG, "Got a GET request for <%s>",  uri);

  /* Don't allow any ".."s in the path, to avoid exposing stuff outside */
  /* of the docroot.  This test is both overzealous and underzealous: */
  /* it forbids aceptable paths like "/this/one..here", but it doesn't */
  /* do anything to prevent symlink following." */
  if (strstr(uri, "..")) {
    LOG_PRINT(LOG_DEBUG, "attempt to upper dir!");
    LOG_PRINT(LOG_INFO, "%s refuse directory", address);
    err_no = 3;
    goto forbidden;
  }

  ox_strlcpy(md5, uri+1+8+1, 33);//这里处理URL
  if(ox_ismd5(md5) == -1) {
    LOG_PRINT(LOG_DEBUG, "Url [%s] is Not a OX Request.", md5);
    LOG_PRINT(LOG_INFO, "%s refuse url illegal", address);
    err_no = 8;
    goto err;
  }

  evthr_t *thread = ox_cbs_get_request_thr(req);
  thr_arg_t *thr_arg = (thr_arg_t *)evthr_get_aux(thread);

  evhtp_kvs_t *params;
  params = req->uri->query;
  if(params != NULL) {
    if(vars.disable_args != 1) {

      const char *str_p = evhtp_kv_find(params, "p");
      if(str_p) {
        size_t p_len = strlen(str_p) + 1;
        passwd = (char *)malloc(p_len);
        if(passwd != NULL) {
          ox_strlcpy(passwd, str_p, p_len);
        }
        LOG_PRINT(LOG_DEBUG, "passwd = %s", passwd);
      }
      else {
        err_no = 11;
        goto err;
      }
    }
  }
  else {
    err_no = 11;
    goto err;
  }

  ox_req = (ox_req_lock_t *)calloc(1, sizeof(ox_req_lock_t));
  if(ox_req == NULL) {
    LOG_PRINT(LOG_DEBUG, "ox_req calloc failed!");
    LOG_PRINT(LOG_ERROR, "%s fail calloc", address);
    goto err;
  }

  ox_req->md5 = md5;
  ox_req->passwd = passwd;
  ox_req->thr_arg = thr_arg;

  int lock_doc_rst = -1;

  // storage setting
  if (vars.mode == 1) {
    lock_doc_rst = ox_doc_lock(ox_req, req);
  }
  else {
    lock_doc_rst = ox_doc_lock_db(ox_req, req);
  }

  if(lock_doc_rst == 2) {
    LOG_PRINT(LOG_DEBUG, "Lock doc[MD5: %s] failed, path is not exists!", md5);
    err_no = 10;
    goto err;
  }
  else {
    err_no = -1;
  }

  ox_cbs_jreturn(req, err_no, md5, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============_doc_lock() DONE!===============");
  goto done;

 forbidden:
  ox_cbs_jreturn(req, err_no, NULL, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============_doc_lock() FORBIDDEN!===============");
  goto done;

 err:
  ox_cbs_jreturn(req, err_no, NULL, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============_doc_lock() ERROR!===============");

 done:
  free(passwd);
  free(ox_req);
}

void ox_cbs_docs_lock(evhtp_request_t *req, void *arg)
{
  char md5[33];
  char passwd[33];
  char *buff = NULL;
  int post_size = 0;
  int err_no = 0;

  ox_req_lock_t *ox_req = NULL;

  evhtp_connection_t *ev_conn = evhtp_request_get_connection(req);
  struct sockaddr *saddr = ev_conn->saddr;
  struct sockaddr_in *ss = (struct sockaddr_in *)saddr;
  char address[16];

  int req_method = evhtp_request_get_method(req);
  if(req_method >= 16) {
    req_method = 16;
  }

  LOG_PRINT(LOG_DEBUG, "Method: %d", req_method);
  if(strcmp(method_strmap[req_method], "POST") != 0) {
    LOG_PRINT(LOG_DEBUG, "Request Method Not Support.");
    err_no = 2;
    goto err;
  }

  const char *xff_address = evhtp_header_find(req->headers_in, "X-Forwarded-For");
  if(xff_address) {
    inet_aton(xff_address, &ss->sin_addr);
  }
  else {
    inet_aton("0.0.0.0", &ss->sin_addr);
  }
  strncpy(address, inet_ntoa(ss->sin_addr), 16);

  if (vars.up_access != NULL) {
    int acs = ox_access_inet(vars.up_access, ss->sin_addr.s_addr);
    LOG_PRINT(LOG_DEBUG, "access check: %d", acs);
    if(acs == OX_FORBIDDEN) {
      LOG_PRINT(LOG_DEBUG, "check access: ip[%s] forbidden!", address);
      LOG_PRINT(LOG_INFO, "%s refuse post forbidden", address);
      err_no = 3;
      goto forbidden;
    }
    else if (acs == OX_ERROR) {
      LOG_PRINT(LOG_DEBUG, "check access: check ip[%s] failed!", address);
      LOG_PRINT(LOG_ERROR, "%s fail post access %s", address);
      err_no = 0;
      goto err;
    }
  }

  const char *content_len = evhtp_header_find(req->headers_in, "Content-Length");
  if(!content_len) {
    LOG_PRINT(LOG_DEBUG, "Get Content-Length error!");
    LOG_PRINT(LOG_ERROR, "%s fail post content-length", address);
    err_no = 5;
    goto err;
  }
  post_size = atoi(content_len);
  if(post_size <= 0) {
    LOG_PRINT(LOG_DEBUG, "Doc Size is Zero!");
    LOG_PRINT(LOG_ERROR, "%s fail post empty", address);
    err_no = 5;
    goto err;
  }
  if(post_size > vars.max_size_doc) {
    LOG_PRINT(LOG_DEBUG, "Doc Size Too Large!");
    LOG_PRINT(LOG_ERROR, "%s fail post large", address);
    err_no = 7;
    goto err;
  }
  evbuf_t *buf;
  buf = req->buffer_in;
  buff = (char *)calloc(post_size + 1, sizeof(char));
  if(buff == NULL) {
    LOG_PRINT(LOG_DEBUG, "buff malloc failed!");
    LOG_PRINT(LOG_ERROR, "%s fail malloc buff", address);
    err_no = 0;
    goto err;
  }
  int rmblen, evblen;
  if(evbuffer_get_length(buf) <= 0) {
    LOG_PRINT(LOG_DEBUG, "Empty Request!");
    LOG_PRINT(LOG_ERROR, "%s fail post empty", address);
    err_no = 4;
    goto err;
  }
  while((evblen = evbuffer_get_length(buf)) > 0) {
    LOG_PRINT(LOG_DEBUG, "evblen = %d", evblen);
    rmblen = evbuffer_remove(buf, buff, evblen);
    LOG_PRINT(LOG_DEBUG, "rmblen = %d", rmblen);
    if(rmblen < 0) {
      LOG_PRINT(LOG_DEBUG, "evbuffer_remove failed!");
      LOG_PRINT(LOG_ERROR, "%s fail post parse", address);
      err_no = 4;
      goto err;
    }
  }

  evthr_t *thread = ox_cbs_get_request_thr(req);
  thr_arg_t *thr_arg = (thr_arg_t *)evthr_get_aux(thread);

  ox_req = (ox_req_lock_t *)calloc(1, sizeof(ox_req_lock_t));
  ox_req->md5 = md5;
  ox_req->passwd = passwd;
  ox_req->thr_arg = thr_arg;

  cJSON *root, *sub, *chd;
  if((root = cJSON_Parse(buff)) == NULL) {
    err_no = 11;
    goto err;
  }

  int i, j_size = cJSON_GetArraySize(root);
  for (i = 0; i < j_size; i++) {
    sub = cJSON_GetArrayItem(root, i);

    chd = cJSON_GetObjectItem(sub, "md5");
    if (chd == NULL) {
      err_no = 12;
      goto jerr;
    }
    ox_strlcpy(ox_req->md5, chd->valuestring, 33);

    chd = cJSON_GetObjectItem(sub, "passwd");
    if (chd == NULL) {
      err_no = 12;
      goto jerr;
    }
    ox_strlcpy(ox_req->passwd, chd->valuestring, 33);
    if (vars.mode == 1) {
      ox_doc_lock(ox_req, req);
    }
    else {
      ox_doc_lock_db(ox_req, req);
    }
  }
  err_no = -1;

  ox_cbs_jreturn(req, err_no, md5, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============_doc_lock() DONE!===============");
  goto jdone;

 forbidden:
  ox_cbs_jreturn(req, err_no, NULL, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============_doc_lock() FORBIDDEN!===============");
  goto done;

 jerr:
  cJSON_Delete(root);

 err:
  ox_cbs_jreturn(req, err_no, NULL, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============_doc_lock() ERROR!===============");
  goto done;

 jdone:
  cJSON_Delete(root);

 done:
  free(buff);
  free(ox_req);
}

void ox_cbs_doc_unlock(evhtp_request_t *req, void *arg)
{
  char md5[35];
  char *passwd = NULL;
  int err_no = 0;

  ox_req_unlock_t *ox_req = NULL;

  evhtp_connection_t *ev_conn = evhtp_request_get_connection(req);
  struct sockaddr *saddr = ev_conn->saddr;
  struct sockaddr_in *ss = (struct sockaddr_in *)saddr;
  char address[16];

  int req_method = evhtp_request_get_method(req);
  if(req_method >= 16) {
    req_method = 16;
  }

  LOG_PRINT(LOG_DEBUG, "Method: %d", req_method);
  if(strcmp(method_strmap[req_method], "GET") != 0) {
    LOG_PRINT(LOG_DEBUG, "Request Method Not Support.");
    err_no = 2;
    goto err;
  }

  const char *xff_address = evhtp_header_find(req->headers_in, "X-Forwarded-For");
  if(xff_address) {
    inet_aton(xff_address, &ss->sin_addr);
  }
  else {
    //    inet_aton("192.168.1.111", &ss->sin_addr);
    inet_aton("0.0.0.0", &ss->sin_addr);
  }
  strncpy(address, inet_ntoa(ss->sin_addr), 16);

  if (vars.up_access != NULL) {
    int acs = ox_access_inet(vars.up_access, ss->sin_addr.s_addr);
    LOG_PRINT(LOG_DEBUG, "access check: %d", acs);
    if(acs == OX_FORBIDDEN) {
      LOG_PRINT(LOG_DEBUG, "check access: ip[%s] forbidden!", address);
      LOG_PRINT(LOG_INFO, "%s refuse post forbidden", address);
      err_no = 3;
      goto forbidden;
    }
    else if (acs == OX_ERROR) {
      LOG_PRINT(LOG_DEBUG, "check access: check ip[%s] failed!", address);
      LOG_PRINT(LOG_ERROR, "%s fail post access %s", address);
      err_no = 0;
      goto err;
    }
  }

  // 获得uri并解析
  const char *uri = req->uri->path->full;
  if((strlen(uri) == 5 || strlen(uri) == 6) &&
     uri[0]=='/' && uri[1]=='i' && uri[2]=='m' && uri[3]=='g' &&
     uri[4]=='/' && uri[5]=='u' && uri[6]=='n' && uri[7]=='l' && uri[8]=='o' && uri[9]=='c' && uri[10]=='k' && uri[11]=='/') {
    LOG_PRINT(LOG_DEBUG, "Root Request.");
    int fd = -1;
    struct stat st;
    if((fd = open(vars.root_path, O_RDONLY)) == -1) {
      LOG_PRINT(LOG_DEBUG, "Root_page Open Failed. Return Default Page.");
      err_no =3;
      goto err;
    }
    else {
      if (fstat(fd, &st) < 0) {
        /* Make sure the length still matches, now that we
         * opened the file :/ */
        LOG_PRINT(LOG_DEBUG, "Root_page Length fstat Failed. Return Default Page.");
        err_no =3;
        goto err;
      }
      else {
        evbuffer_add_file(req->buffer_out, fd, 0, st.st_size);
      }
    }
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
    evhtp_send_reply(req, EVHTP_RES_OK);
    LOG_PRINT(LOG_DEBUG, "============_doc_del() DONE!===============");
    LOG_PRINT(LOG_INFO, "%s succ root page", address);
    goto done;
  }

  if(strstr(uri, "favicon.ico")) {
    LOG_PRINT(LOG_DEBUG, "favicon.ico Request, Denied.");
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
    ox_cbs_headers_add(req, vars.headers);
    evhtp_send_reply(req, EVHTP_RES_OK);
    goto done;
  }
  LOG_PRINT(LOG_DEBUG, "Got a GET request for <%s>",  uri);

  /* Don't allow any ".."s in the path, to avoid exposing stuff outside */
  /* of the docroot.  This test is both overzealous and underzealous: */
  /* it forbids aceptable paths like "/this/one..here", but it doesn't */
  /* do anything to prevent symlink following." */
  if (strstr(uri, "..")) {
    LOG_PRINT(LOG_DEBUG, "attempt to upper dir!");
    LOG_PRINT(LOG_INFO, "%s refuse directory", address);
    err_no = 3;
    goto forbidden;
  }

  ox_strlcpy(md5, uri+1+10+1, 33);//这里处理URL
  if(ox_ismd5(md5) == -1) {
    LOG_PRINT(LOG_DEBUG, "Url [%s] is Not a OX Request.", md5);
    LOG_PRINT(LOG_INFO, "%s refuse url illegal", address);
    err_no = 8;
    goto err;
  }

  evthr_t *thread = ox_cbs_get_request_thr(req);
  thr_arg_t *thr_arg = (thr_arg_t *)evthr_get_aux(thread);

  evhtp_kvs_t *params;
  params = req->uri->query;
  if(params != NULL) {
    if(vars.disable_args != 1) {

      const char *str_p = evhtp_kv_find(params, "p");
      if(str_p) {
        size_t p_len = strlen(str_p) + 1;
        passwd = (char *)malloc(p_len);
        if(passwd != NULL) {
          ox_strlcpy(passwd, str_p, p_len);
        }
        LOG_PRINT(LOG_DEBUG, "passwd = %s", passwd);
      }
      else {
        err_no = 2;
        goto err;
      }
    }
  }
  else {
    err_no = 2;
    goto err;
  }

  ox_req = (ox_req_unlock_t *)calloc(1, sizeof(ox_req_unlock_t));
  if(ox_req == NULL) {
    LOG_PRINT(LOG_DEBUG, "ox_req calloc failed!");
    LOG_PRINT(LOG_ERROR, "%s fail calloc", address);
    goto err;
  }

  ox_req->md5 = md5;
  ox_req->passwd = passwd;
  ox_req->thr_arg = thr_arg;

  int unlock_doc_rst = -1;

  // storage setting
  if (vars.mode == 1) {
    unlock_doc_rst = ox_doc_unlock(ox_req, req);
  }
  else {
    unlock_doc_rst = ox_doc_unlock_db(ox_req, req);
  }

  if(unlock_doc_rst == 2) {
    LOG_PRINT(LOG_DEBUG, "Lock doc[MD5: %s] failed, path is not exists!", md5);
    err_no = 10;
    goto err;
  }
  else {
    err_no = -1;
  }

  ox_cbs_jreturn(req, err_no, md5, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============_doc_del() DONE!===============");
  goto done;

 forbidden:
  ox_cbs_jreturn(req, err_no, NULL, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============_doc_del() FORBIDDEN!===============");
  goto done;

 err:
  ox_cbs_jreturn(req, err_no, NULL, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============_doc_del() ERROR!===============");

 done:
  free(ox_req);
  free(passwd);
}

void ox_cbs_docs_unlock(evhtp_request_t *req, void *arg)
{
  char md5[33];
  char passwd[33];
  char *buff = NULL;
  int post_size = 0;
  int err_no = 0;

  ox_req_unlock_t *ox_req = NULL;

  evhtp_connection_t *ev_conn = evhtp_request_get_connection(req);
  struct sockaddr *saddr = ev_conn->saddr;
  struct sockaddr_in *ss = (struct sockaddr_in *)saddr;
  char address[16];

  int req_method = evhtp_request_get_method(req);
  if(req_method >= 16) {
    req_method = 16;
  }

  LOG_PRINT(LOG_DEBUG, "Method: %d", req_method);
  if(strcmp(method_strmap[req_method], "POST") != 0) {
    LOG_PRINT(LOG_DEBUG, "Request Method Not Support.");
    err_no = 2;
    goto err;
  }

  const char *xff_address = evhtp_header_find(req->headers_in, "X-Forwarded-For");
  if(xff_address) {
    inet_aton(xff_address, &ss->sin_addr);
  }
  else {
    //    inet_aton("192.168.1.111", &ss->sin_addr);
    inet_aton("0.0.0.0", &ss->sin_addr);
  }
  strncpy(address, inet_ntoa(ss->sin_addr), 16);

  if (vars.up_access != NULL) {
    int acs = ox_access_inet(vars.up_access, ss->sin_addr.s_addr);
    LOG_PRINT(LOG_DEBUG, "access check: %d", acs);
    if(acs == OX_FORBIDDEN) {
      LOG_PRINT(LOG_DEBUG, "check access: ip[%s] forbidden!", address);
      LOG_PRINT(LOG_INFO, "%s refuse post forbidden", address);
      err_no = 3;
      goto forbidden;
    }
    else if (acs == OX_ERROR) {
      LOG_PRINT(LOG_DEBUG, "check access: check ip[%s] failed!", address);
      LOG_PRINT(LOG_ERROR, "%s fail post access %s", address);
      err_no = 0;
      goto err;
    }
  }

  const char *content_len = evhtp_header_find(req->headers_in, "Content-Length");
  if(!content_len) {
    LOG_PRINT(LOG_DEBUG, "Get Content-Length error!");
    LOG_PRINT(LOG_ERROR, "%s fail post content-length", address);
    err_no = 5;
    goto err;
  }
  post_size = atoi(content_len);
  if(post_size <= 0) {
    LOG_PRINT(LOG_DEBUG, "Doc Size is Zero!");
    LOG_PRINT(LOG_ERROR, "%s fail post empty", address);
    err_no = 5;
    goto err;
  }
  if(post_size > vars.max_size_doc) {
    LOG_PRINT(LOG_DEBUG, "Doc Size Too Large!");
    LOG_PRINT(LOG_ERROR, "%s fail post large", address);
    err_no = 7;
    goto err;
  }
  evbuf_t *buf;
  buf = req->buffer_in;
  buff = (char *)calloc(post_size + 1, sizeof(char));
  if(buff == NULL) {
    LOG_PRINT(LOG_DEBUG, "buff malloc failed!");
    LOG_PRINT(LOG_ERROR, "%s fail malloc buff", address);
    err_no = 0;
    goto err;
  }
  int rmblen, evblen;
  if(evbuffer_get_length(buf) <= 0) {
    LOG_PRINT(LOG_DEBUG, "Empty Request!");
    LOG_PRINT(LOG_ERROR, "%s fail post empty", address);
    err_no = 4;
    goto err;
  }
  while((evblen = evbuffer_get_length(buf)) > 0) {
    LOG_PRINT(LOG_DEBUG, "evblen = %d", evblen);
    rmblen = evbuffer_remove(buf, buff, evblen);
    LOG_PRINT(LOG_DEBUG, "rmblen = %d", rmblen);
    if(rmblen < 0) {
      LOG_PRINT(LOG_DEBUG, "evbuffer_remove failed!");
      LOG_PRINT(LOG_ERROR, "%s fail post parse", address);
      err_no = 4;
      goto err;
    }
  }

  evthr_t *thread = ox_cbs_get_request_thr(req);
  thr_arg_t *thr_arg = (thr_arg_t *)evthr_get_aux(thread);

  ox_req = (ox_req_unlock_t *)calloc(1, sizeof(ox_req_unlock_t));
  ox_req->md5 = md5;
  ox_req->passwd = passwd;
  ox_req->thr_arg = thr_arg;

  cJSON *root, *sub, *chd;
  if((root = cJSON_Parse(buff)) == NULL) {
    err_no = 11;
    goto err;
  }

  int i, j_size = cJSON_GetArraySize(root);
  for (i = 0; i < j_size; i++) {
    sub = cJSON_GetArrayItem(root, i);

    chd = cJSON_GetObjectItem(sub, "md5");
    if (chd == NULL) {
      err_no = 12;
      goto jerr;
    }
    ox_strlcpy(ox_req->md5, chd->valuestring, 33);

    chd = cJSON_GetObjectItem(sub, "passwd");
    if (chd == NULL) {
      err_no = 12;
      goto jerr;
    }
    ox_strlcpy(ox_req->passwd, chd->valuestring, 33);
    if (vars.mode == 1) {
      ox_doc_unlock(ox_req, req);
    }
    else {
      ox_doc_unlock_db(ox_req, req);
    }
  }
  err_no = -1;

  ox_cbs_jreturn(req, err_no, md5, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============_doc_del() DONE!===============");
  goto jdone;

 forbidden:
  ox_cbs_jreturn(req, err_no, NULL, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============_doc_del() FORBIDDEN!===============");
  goto done;

 jerr:
  cJSON_Delete(root);

 err:
  ox_cbs_jreturn(req, err_no, NULL, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============_doc_del() ERROR!===============");
  goto done;

 jdone:
  cJSON_Delete(root);

 done:
  free(buff);
  free(ox_req);
}
