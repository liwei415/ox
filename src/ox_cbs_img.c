#include "ox_cbs_img.h"

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

int _binary_parse_img(evhtp_request_t *req, const char *content_type, const char *address, const char *buff, int post_size)
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
  if (ox_isimg(ctype) != 1) {
    err_no = 1;
  }
  magic_close(magic_cookie);

  if (err_no == 1) {
    LOG_PRINT(LOG_DEBUG, "fileType[%s] is Not Supported!", ctype);
    LOG_PRINT(LOG_ERROR, "%s fail post type", address);
    goto done;
  }

  char md5sum[33];
  LOG_PRINT(LOG_DEBUG, "Begin to Save Image...");
  evthr_t *thread = ox_cbs_get_request_thr(req);
  thr_arg_t *thr_arg = (thr_arg_t *)evthr_get_aux(thread);
  if(ox_img_save(thr_arg, buff, post_size, md5sum) == -1) {
    LOG_PRINT(LOG_DEBUG, "Image Save Failed!");
    LOG_PRINT(LOG_ERROR, "%s fail post save", address);
    goto done;
  }

  err_no = -1;
  LOG_PRINT(LOG_INFO, "%s succ post pic:%s size:%d", address, md5sum, post_size);
  ox_cbs_jreturn(req, err_no, md5sum, post_size);

done:
    return err_no;
}

void _cbs_img_post(evhtp_request_t *req)
{
  int post_size = 0;
  char *buff = NULL;
  int err_no = 0;
  int ret_json = 1;

  evhtp_connection_t *ev_conn = evhtp_request_get_connection(req);
  struct sockaddr *saddr = ev_conn->saddr;
  struct sockaddr_in *ss = (struct sockaddr_in *)saddr;
  char address[16];

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
    LOG_PRINT(LOG_DEBUG, "Image Size is Zero!");
    LOG_PRINT(LOG_ERROR, "%s fail post empty", address);
    err_no = 5;
    goto err;
  }
  if(post_size > vars.max_size_img) {
    LOG_PRINT(LOG_DEBUG, "Image Size Too Large!");
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
  buff = (char *)malloc(post_size);
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
    err_no = _binary_parse_img(req, content_type, address, buff, post_size);
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
  LOG_PRINT(LOG_DEBUG, "============_img_post() FORBIDDEN!===============");
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

void _cbs_img_get(evhtp_request_t *req)
{
  char *md5 = NULL;
  char *fmt = NULL;
  char *type = NULL;
  char *buff = NULL;
  size_t len;
  ox_req_img_t *ox_req = NULL;

  evhtp_connection_t *ev_conn = evhtp_request_get_connection(req);
  struct sockaddr *saddr = ev_conn->saddr;
  struct sockaddr_in *ss = (struct sockaddr_in *)saddr;
  char address[16];

  const char *xff_address = evhtp_header_find(req->headers_in, "X-Forwarded-For");
  if(xff_address) {
    inet_aton(xff_address, &ss->sin_addr);
  }
  else {
    inet_aton("192.168.1.111", &ss->sin_addr);
  }
  strncpy(address, inet_ntoa(ss->sin_addr), 16);

  if(vars.down_access != NULL) {
    int acs = ox_access_inet(vars.down_access, ss->sin_addr.s_addr);
    LOG_PRINT(LOG_DEBUG, "access check: %d", acs);

    if(acs == OX_FORBIDDEN) {
      LOG_PRINT(LOG_DEBUG, "check access: ip[%s] forbidden!", address);
      LOG_PRINT(LOG_INFO, "%s refuse get forbidden", address);
      goto forbidden;
    }
    else if(acs == OX_ERROR) {
      LOG_PRINT(LOG_DEBUG, "check access: check ip[%s] failed!", address);
      LOG_PRINT(LOG_ERROR, "%s fail get access", address);
      goto err;
    }
  }

  // 获得uri并解析
  const char *uri = req->uri->path->full;
  if((strlen(uri) == 4 || strlen(uri) == 5) &&
     uri[0]=='/' && uri[1]=='i' && uri[2]=='m' && uri[3]=='g') {
    LOG_PRINT(LOG_DEBUG, "Root Request.");
    int fd = -1;
    struct stat st;
    if((fd = open(vars.root_path, O_RDONLY)) == -1) {
      LOG_PRINT(LOG_DEBUG, "Root_page Open Failed. Return Default Page.");
      evbuffer_add_printf(req->buffer_out, "<html><body><h1>Welcome to OX world! Please let me know the image name</h1></body></html>");
    }
    else {
      if (fstat(fd, &st) < 0) {
        /* Make sure the length still matches, now that we
         * opened the file :/ */
        LOG_PRINT(LOG_DEBUG, "Root_page Length fstat Failed. Return Default Page.");
        evbuffer_add_printf(req->buffer_out, "<html><body><h1>Welcome to OX world! Please let me know the image name</h1></body></html>");
      }
      else {
        evbuffer_add_file(req->buffer_out, fd, 0, st.st_size);
      }
    }
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
    evhtp_send_reply(req, EVHTP_RES_OK);
    LOG_PRINT(LOG_DEBUG, "============_img_get() DONE!===============");
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
  /* This holds the content we're sending. */

  evthr_t *thread = ox_cbs_get_request_thr(req);
  thr_arg_t *thr_arg = (thr_arg_t *)evthr_get_aux(thread);

  int width, height, proportion, gray, x, y, rotate, quality, sv;
  width = 0;
  height = 0;
  proportion = 1;
  gray = 0;
  x = -1;
  y = -1;
  rotate = 0;
  quality = 0;
  sv = 0;

  evhtp_kvs_t *params;
  params = req->uri->query;
  if(params != NULL) {
    if(vars.disable_args != 1) {
      const char *str_w = evhtp_kv_find(params, "w");
      width = (str_w) ? atoi(str_w) : 0;

      const char *str_h = evhtp_kv_find(params, "h");
      height = (str_h) ? atoi(str_h) : 0;

      const char *str_p = evhtp_kv_find(params, "p");
      proportion = (str_p) ? atoi(str_p) : 1;

      const char *str_g = evhtp_kv_find(params, "g");
      gray = (str_g) ? atoi(str_g) : 0;

      const char *str_x = evhtp_kv_find(params, "x");
      x = (str_x) ? atoi(str_x) : -1;

      const char *str_y = evhtp_kv_find(params, "y");
      y = (str_y) ? atoi(str_y) : -1;

      if(x != -1 || y != -1) {
        proportion = 1;
      }

      const char *str_r = evhtp_kv_find(params, "r");
      rotate = (str_r) ? atoi(str_r) : 0;

      const char *str_q = evhtp_kv_find(params, "q");
      quality = (str_q) ? atoi(str_q) : 0;

      const char *str_f = evhtp_kv_find(params, "f");
      if(str_f) {
        size_t fmt_len = strlen(str_f) + 1;
        fmt = (char *)malloc(fmt_len);
        if(fmt != NULL) {
          ox_strlcpy(fmt, str_f, fmt_len);
        }
        LOG_PRINT(LOG_DEBUG, "fmt = %s", fmt);
      }
    }

    if(vars.disable_type != 1) {
      const char *str_t = evhtp_kv_find(params, "t");
      if(str_t) {
        size_t type_len = strlen(str_t) + 1;
        type = (char *)malloc(type_len);
        if(type != NULL) {
          ox_strlcpy(type, str_t, type_len);
        }
        LOG_PRINT(LOG_DEBUG, "type = %s", type);
      }
    }
  }
  else {
    sv = 1;
  }

  quality = (quality != 0 ? quality : vars.quality);
  ox_req = (ox_req_img_t *)malloc(sizeof(ox_req_img_t));
  if(ox_req == NULL) {
    LOG_PRINT(LOG_DEBUG, "ox_req malloc failed!");
    LOG_PRINT(LOG_ERROR, "%s fail malloc", address);
    goto err;
  }

  ox_req->md5 = md5;
  ox_req->type = type;
  ox_req->width = width;
  ox_req->height = height;
  ox_req->proportion = proportion;
  ox_req->gray = gray;
  ox_req->x = x;
  ox_req->y = y;
  ox_req->rotate = rotate;
  ox_req->quality = quality;
  ox_req->fmt = (fmt != NULL ? fmt : vars.format);
  ox_req->sv = sv;
  ox_req->thr_arg = thr_arg;

  int get_img_rst = -1;

  // storage setting
  if (vars.mode == 1) {
    get_img_rst = ox_img_get(ox_req, req); //filesystem
  }
  else {
    get_img_rst = ox_img_get_db(ox_req, req); //db
  }

  if(get_img_rst == -1) {
    LOG_PRINT(LOG_DEBUG, "OX Requset Get Image[MD5: %s] Failed!", ox_req->md5);
    if(type) {
      LOG_PRINT(LOG_ERROR, "%s fail pic:%s t:%s", address, md5, type);
    }
    else {
      LOG_PRINT(LOG_ERROR, "%s fail pic:%s w:%d h:%d p:%d g:%d x:%d y:%d r:%d q:%d f:%s",
                address, md5, width, height, proportion, gray, x, y, rotate, quality, ox_req->fmt);
    }
    goto err;
  }
  if(get_img_rst == 2) {
    LOG_PRINT(LOG_DEBUG, "Etag Matched Return 304 EVHTP_RES_NOTMOD.");
    if(type) {
      LOG_PRINT(LOG_INFO, "%s succ 304 pic:%s t:%s", address, md5, type);
    }
    else {
      LOG_PRINT(LOG_INFO, "%s succ 304 pic:%s w:%d h:%d p:%d g:%d x:%d y:%d r:%d q:%d f:%s",
                address, md5, width, height, proportion, gray, x, y, rotate, quality, ox_req->fmt);
    }
    evhtp_send_reply(req, EVHTP_RES_NOTMOD);
    goto done;
  }

  len = evbuffer_get_length(req->buffer_out);
  LOG_PRINT(LOG_DEBUG, "get buffer length: %d", len);

  LOG_PRINT(LOG_DEBUG, "Got the File!");
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "image/jpeg", 0, 0));
  ox_cbs_headers_add(req, vars.headers);
  evhtp_send_reply(req, EVHTP_RES_OK);
  if (type) {
    LOG_PRINT(LOG_INFO, "%s succ pic:%s t:%s size:%d", address, md5, type, len);
  }
  else {
    LOG_PRINT(LOG_INFO, "%s succ pic:%s w:%d h:%d p:%d g:%d x:%d y:%d r:%d q:%d f:%s size:%d",
              address, md5, width, height, proportion, gray, x, y, rotate, quality, ox_req->fmt,
              len);
  }
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
  free(ox_req);
  free(buff);
}

void ox_cbs_img(evhtp_request_t *req, void *arg)
{

  int req_method = evhtp_request_get_method(req);
  if(req_method >= 16) {
    req_method = 16;
  }

  LOG_PRINT(LOG_DEBUG, "Method: %d", req_method);
  if(strcmp(method_strmap[req_method], "POST") == 0) {
    _cbs_img_post(req);
    return;
  }
  else if(strcmp(method_strmap[req_method], "GET") == 0) {
    _cbs_img_get(req);
    return;
  }
  else {
    LOG_PRINT(LOG_DEBUG, "Request Method Not Support.");
    goto err;
  }

 err:
  evbuffer_add_printf(req->buffer_out, "<html><body><h1>404 Not Found!</h1></body></html>");
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
  evhtp_send_reply(req, EVHTP_RES_NOTFOUND);
  LOG_PRINT(LOG_DEBUG, "============ox_cbs_get() ERROR!===============");

}

void _cbs_img_del(evhtp_request_t *req)
{
  char md5[35];
  int err_no = 0;

  ox_req_img_t *ox_req = NULL;

  evhtp_connection_t *ev_conn = evhtp_request_get_connection(req);
  struct sockaddr *saddr = ev_conn->saddr;
  struct sockaddr_in *ss = (struct sockaddr_in *)saddr;
  char address[16];

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
    LOG_PRINT(LOG_DEBUG, "============_img_del() DONE!===============");
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

  ox_req = (ox_req_img_t *)calloc(1, sizeof(ox_req_img_t));
  ox_req->md5 = md5;
  ox_req->thr_arg = thr_arg;

  int del_img_rst = -1;

  // storage setting
  if (vars.mode == 1) {
    del_img_rst = ox_img_del(ox_req, req);
  }
  else {
    del_img_rst = ox_img_del_db(ox_req, req);
  }

  if(del_img_rst == 2) {
    LOG_PRINT(LOG_DEBUG, "Del Img[MD5: %s] failed, path is not exists!", md5);
    err_no = 10;
    goto err;
  }
  else {
    err_no = -1;
  }

  ox_cbs_jreturn(req, err_no, md5, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============_img_del() DONE!===============");
  goto done;

 forbidden:
  ox_cbs_jreturn(req, err_no, NULL, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============_img_del() FORBIDDEN!===============");
  goto done;

 err:
  ox_cbs_jreturn(req, err_no, NULL, 0);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============_img_del() ERROR!===============");

 done:
  free(ox_req);
}

void ox_cbs_img_del(evhtp_request_t *req, void *arg)
{

  int req_method = evhtp_request_get_method(req);
  if(req_method >= 16) {
    req_method = 16;
  }

  LOG_PRINT(LOG_DEBUG, "Method: %d", req_method);
  if(strcmp(method_strmap[req_method], "GET") == 0) {
    _cbs_img_del(req);
    return;
  }
  else {
    LOG_PRINT(LOG_DEBUG, "Request Method Not Support.");
    goto err;
  }

 err:
  evbuffer_add_printf(req->buffer_out, "<html><body><h1>404 Not Found!</h1></body></html>");
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
  evhtp_send_reply(req, EVHTP_RES_NOTFOUND);
  LOG_PRINT(LOG_DEBUG, "============ox_cbs_get() ERROR!===============");

}
