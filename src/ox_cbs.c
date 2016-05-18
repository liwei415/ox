#include "ox_cbs.h"

static const char * post_error_list[] = {
  "Internal error.",
  "File type not support.",
  "Request method error.",
  "Access error.",
  "Request body parse error.",
  "Content-Length error.",
  "Content-Type error.",
  "File too large.",
  "Request url illegal.",
  "Image not existed."
};

static const char * method_strmap[] = {
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

int ox_cbs_etag_set(evhtp_request_t *req, char *buff, size_t len)
{
  int result = 1;
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
  LOG_PRINT(LOG_DEBUG, "md5: %s", md5sum);

  const char *etag_var = evhtp_header_find(req->headers_in, "If-None-Match");
  LOG_PRINT(LOG_DEBUG, "If-None-Match: %s", etag_var);
  if(etag_var == NULL) {
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Etag", md5sum, 0, 1));
  }
  else {
    if(strncmp(md5sum, etag_var, 32) == 0) {
      result = 2;
    }
    else {
      evhtp_headers_add_header(req->headers_out, evhtp_header_new("Etag", md5sum, 0, 1));
    }
  }
  return result;
}

void ox_cbs_headers_free(ox_cbs_headers_conf_t *hcf)
{
  if(hcf == NULL) {
    return;
  }
  ox_cbs_headers_t *headers = hcf->headers;
  while(headers) {
    hcf->headers = headers->next;
    free(headers->value);
    free(headers);
    headers = hcf->headers;
  }
  free(hcf);
}

ox_cbs_headers_conf_t * ox_cbs_get_headers_conf(const char *hdr_str)
{
  if(hdr_str == NULL) {
    return NULL;
  }
  ox_cbs_headers_conf_t *hdrconf = (ox_cbs_headers_conf_t *)malloc(sizeof(ox_cbs_headers_conf_t));
  if(hdrconf == NULL) {
    return NULL;
  }
  hdrconf->n = 0;
  hdrconf->headers = NULL;
  size_t hdr_len = strlen(hdr_str);
  char *hdr = (char *)malloc(hdr_len);
  if(hdr == NULL) {
    return NULL;
  }
  strncpy(hdr, hdr_str, hdr_len);
  char *start = hdr, *end;
  while(start <= hdr+hdr_len) {
    end = strchr(start, ';');
    end = (end) ? end : hdr+hdr_len;
    char *key = start;
    char *value = strchr(key, ':');
    size_t key_len = value - key;
    if (value) {
      ox_cbs_header_t *this_header = (ox_cbs_header_t *)malloc(sizeof(ox_cbs_header_t));
      if (this_header == NULL) {
        start = end + 1;
        continue;
      }
      (void) memset(this_header, 0, sizeof(ox_cbs_header_t));
      size_t value_len;
      value++;
      value_len = end - value;

      strncpy(this_header->key, key, key_len);
      strncpy(this_header->value, value, value_len);

      ox_cbs_headers_t *headers = (ox_cbs_headers_t *)malloc(sizeof(ox_cbs_headers_t));
      if (headers == NULL) {
        start = end + 1;
        continue;
      }

      headers->value = this_header;
      headers->next = hdrconf->headers;
      hdrconf->headers = headers;
      hdrconf->n++;
    }
    start = end + 1;
  }
  free(hdr);
  return hdrconf;
}

static int ox_headers_add(evhtp_request_t *req, ox_cbs_headers_conf_t *hcf)
{
  if(hcf == NULL) {
    return -1;
  }
  ox_cbs_headers_t *headers = hcf->headers;
  LOG_PRINT(LOG_DEBUG, "headers: %d", hcf->n);

  while(headers) {
    evhtp_headers_add_header(req->headers_out,
                             evhtp_header_new(headers->value->key,
                                              headers->value->value, 1, 1));
    headers = headers->next;
  }
  return 1;
}

static evthr_t *_get_request_thr(evhtp_request_t *request)
{
  evhtp_connection_t *htpconn;
  evthr_t *thread;

  htpconn = evhtp_request_get_connection(request);
  thread  = htpconn->thread;

  return thread;
}

int ox_cbs_on_header_value(multipart_parser* p, const char *at, size_t length)
{
  mp_arg_t *mp_arg = (mp_arg_t *)multipart_parser_get_data(p);
  char *filename = ox_strnstr(at, "filename=", length);
  char *nameend = NULL;
  if(filename) {
    filename += 9;
    if(filename[0] == '\"') {
      filename++;
      nameend = ox_strnchr(filename, '\"', length-(filename-at));
      if(!nameend) {
        mp_arg->check_name = -1;
      }
      else {
        nameend[0] = '\0';
        char fileType[32];
        LOG_PRINT(LOG_DEBUG, "File[%s]", filename);
        if(ox_file_type(filename, fileType) == -1) {
          LOG_PRINT(LOG_DEBUG, "Get Type of File[%s] Failed!", filename);
          mp_arg->check_name = -1;
        }
        else {
          LOG_PRINT(LOG_DEBUG, "fileType[%s]", fileType);
          if(ox_isimg(fileType) != 1) {
            LOG_PRINT(LOG_DEBUG, "fileType[%s] is Not Supported!", fileType);
            mp_arg->check_name = -1;
          }
        }
      }
    }
    if(filename[0] != '\0' && mp_arg->check_name == -1) {
      LOG_PRINT(LOG_ERROR, "%s fail post type", mp_arg->address);
      evbuffer_add_printf(mp_arg->req->buffer_out,
                          "<h1>File: %s</h1>\n"
                          "<p>File type is not supported!</p>\n",
                          filename);
    }
  }
  //multipart_parser_set_data(p, mp_arg);
  char *header_value = (char *)malloc(length+1);
  snprintf(header_value, length+1, "%s", at);
  LOG_PRINT(LOG_DEBUG, "header_value %d %s", length, header_value);
  free(header_value);
  return 0;
}

int ox_cbs_on_chunk_data(multipart_parser* p, const char *at, size_t length)
{
  mp_arg_t *mp_arg = (mp_arg_t *)multipart_parser_get_data(p);
  mp_arg->partno++;
  if(mp_arg->check_name == -1) {
    mp_arg->check_name = 0;
    return 0;
  }
  if(length < 1) {
    return 0;
  }
  //multipart_parser_set_data(p, mp_arg);
  char md5sum[33];
  if(ox_img_save(mp_arg->thr_arg, at, length, md5sum) == -1) {
    LOG_PRINT(LOG_DEBUG, "Image Save Failed!");
    LOG_PRINT(LOG_ERROR, "%s fail post save", mp_arg->address);
    evbuffer_add_printf(mp_arg->req->buffer_out,
                        "<h1>Failed!</h1>\n"
                        "<p>File save failed!</p>\n");
  }
  else {
    mp_arg->succno++;
    LOG_PRINT(LOG_INFO, "%s succ post pic:%s size:%d", mp_arg->address, md5sum, length);
    evbuffer_add_printf(mp_arg->req->buffer_out,
                        "<h1>MD5: %s</h1>\n"
                        "Image upload successfully! You can get this image via this address:<br/><br/>\n"
                        "<a href=\"/%s\">http://yourhostname:%d/%s</a>?w=width&h=height&g=isgray&x=position_x&y=position_y&r=rotate&q=quality&f=format\n",
                        md5sum, md5sum, vars.port, md5sum);
  }
  return 0;
}

int _jreturn(evhtp_request_t *req, int err_no, const char *md5sum, int post_size)
{
  //json sample:
  //{"ret":true,"info":{"size":"1024", "md5":"cnbf35fd4b0059d3218f7630bc56a6f4"}}
  //{"ret":false,"error":{"code":"1","message":"\u9a8c\u8bc1\u5931\u8d25"}}
  cJSON *j_ret = cJSON_CreateObject();
  cJSON *j_ret_info = cJSON_CreateObject();
  if(err_no == -1) {
    cJSON_AddBoolToObject(j_ret, "ret", 1);
    cJSON_AddStringToObject(j_ret_info, "md5", md5sum);
    cJSON_AddNumberToObject(j_ret_info, "size", post_size);
    cJSON_AddItemToObject(j_ret, "info", j_ret_info);
  }
  else {
    cJSON_AddBoolToObject(j_ret, "ret", 0);
    cJSON_AddNumberToObject(j_ret_info, "code", err_no);
    LOG_PRINT(LOG_DEBUG, "post_error_list[%d]: %s", err_no, post_error_list[err_no]);
    cJSON_AddStringToObject(j_ret_info, "message", post_error_list[err_no]);
    cJSON_AddItemToObject(j_ret, "error", j_ret_info);
  }
  char *ret_str_unformat = cJSON_PrintUnformatted(j_ret);
  LOG_PRINT(LOG_DEBUG, "ret_str_unformat: %s", ret_str_unformat);
  evbuffer_add_printf(req->buffer_out, "%s", ret_str_unformat);
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "application/json", 0, 0));

  cJSON_Delete(j_ret);
  free(ret_str_unformat);

  return 0;
}

int _binary_parse(evhtp_request_t *req, const char *content_type, const char *address, const char *buff, int post_size)
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
  evthr_t *thread = _get_request_thr(req);
  thr_arg_t *thr_arg = (thr_arg_t *)evthr_get_aux(thread);
  if(ox_img_save(thr_arg, buff, post_size, md5sum) == -1) {
    LOG_PRINT(LOG_DEBUG, "Image Save Failed!");
    LOG_PRINT(LOG_ERROR, "%s fail post save", address);
    goto done;
  }

  err_no = -1;
  LOG_PRINT(LOG_INFO, "%s succ post pic:%s size:%d", address, md5sum, post_size);
  _jreturn(req, err_no, md5sum, post_size);

done:
    return err_no;
}

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
  evthr_t *thread = _get_request_thr(req);
  thr_arg_t *thr_arg = (thr_arg_t *)evthr_get_aux(thread);
  if(ox_doc_save(thr_arg, buff, post_size, md5sum) == -1) {
    LOG_PRINT(LOG_DEBUG, "Doc save failed!");
    LOG_PRINT(LOG_ERROR, "%s fail post save", address);
    goto done;
  }

  err_no = -1;
  LOG_PRINT(LOG_INFO, "%s succ post pic:%s size:%d", address, md5sum, post_size);
  _jreturn(req, err_no, md5sum, post_size);

done:
    return err_no;
}

int _binary_parse_mov(evhtp_request_t *req, const char *content_type, const char *address, const char *buff, int post_size)
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
  if (ox_ismov(ctype) != 1) {
    err_no = 1;
  }
  magic_close(magic_cookie);

  if (err_no == 1) {
    LOG_PRINT(LOG_DEBUG, "fileType[%s] is Not Supported!", ctype);
    LOG_PRINT(LOG_ERROR, "%s fail post type", address);
    goto done;
  }

  char md5sum[33];
  LOG_PRINT(LOG_DEBUG, "Begin to save movie...");
  evthr_t *thread = _get_request_thr(req);
  thr_arg_t *thr_arg = (thr_arg_t *)evthr_get_aux(thread);
  if(ox_mov_save(thr_arg, buff, post_size, md5sum) == -1) {
    LOG_PRINT(LOG_DEBUG, "Movie save failed!");
    LOG_PRINT(LOG_ERROR, "%s fail post save", address);
    goto done;
  }

  err_no = -1;
  LOG_PRINT(LOG_INFO, "%s succ post pic:%s size:%d", address, md5sum, post_size);
  _jreturn(req, err_no, md5sum, post_size);

done:
    return err_no;
}

int _multipart_parse(evhtp_request_t *req, const char *content_type, const char *address, const char *buff, int post_size)
{
  int err_no = 0;
  char *boundary = NULL;
  char *boundary_end = NULL;
  char *boundaryPattern = NULL;
  int boundary_len = 0;
  mp_arg_t *mp_arg = NULL;

  evbuffer_add_printf(req->buffer_out,
                      "<html>\n<head>\n"
                      "<title>Upload Result</title>\n"
                      "</head>\n"
                      "<body>\n");

  if(strstr(content_type, "boundary") == 0) {
    LOG_PRINT(LOG_DEBUG, "boundary NOT found!");
    LOG_PRINT(LOG_ERROR, "%s fail post parse", address);
    err_no = 6;
    goto done;
  }

  boundary = strchr(content_type, '=');
  boundary++;
  boundary_len = strlen(boundary);

  if(boundary[0] == '"') {
    boundary++;
    boundary_end = strchr(boundary, '"');
    if (!boundary_end) {
      LOG_PRINT(LOG_DEBUG, "Invalid boundary in multipart/form-data POST data");
      LOG_PRINT(LOG_ERROR, "%s fail post parse", address);
      err_no = 6;
      goto done;
    }
  }
  else {
    /* search for the end of the boundary */
    boundary_end = strpbrk(boundary, ",;");
  }
  if (boundary_end) {
    boundary_end[0] = '\0';
    boundary_len = boundary_end-boundary;
  }

  LOG_PRINT(LOG_DEBUG, "boundary Find. boundary = %s", boundary);
  boundaryPattern = (char *)malloc(boundary_len + 3);
  if(boundaryPattern == NULL) {
    LOG_PRINT(LOG_DEBUG, "boundarypattern malloc failed!");
    LOG_PRINT(LOG_ERROR, "%s fail malloc", address);
    err_no = 0;
    goto done;
  }
  snprintf(boundaryPattern, boundary_len + 3, "--%s", boundary);
  LOG_PRINT(LOG_DEBUG, "boundaryPattern = %s, strlen = %d", boundaryPattern, (int)strlen(boundaryPattern));

  multipart_parser* parser = multipart_parser_init(boundaryPattern);
  if(!parser) {
    LOG_PRINT(LOG_DEBUG, "Multipart_parser Init Failed!");
    LOG_PRINT(LOG_ERROR, "%s fail post save", address);
    err_no = 0;
    goto done;
  }
  mp_arg = (mp_arg_t *)malloc(sizeof(mp_arg_t));
  if(!mp_arg) {
    LOG_PRINT(LOG_DEBUG, "Multipart_parser Arg Malloc Failed!");
    LOG_PRINT(LOG_ERROR, "%s fail post save", address);
    err_no = 0;
    goto done;
  }

  evthr_t *thread = _get_request_thr(req);
  thr_arg_t *thr_arg = (thr_arg_t *)evthr_get_aux(thread);
  mp_arg->req = req;
  mp_arg->thr_arg = thr_arg;
  ox_strlcpy(mp_arg->address, address, 16);
  mp_arg->partno = 0;
  mp_arg->succno = 0;
  mp_arg->check_name = 0;
  multipart_parser_set_data(parser, mp_arg);
  multipart_parser_execute(parser, buff, post_size);
  multipart_parser_free(parser);

  if(mp_arg->succno == 0) {
    evbuffer_add_printf(req->buffer_out, "<h1>Upload Failed!</h1>\n");
  }

  evbuffer_add_printf(req->buffer_out, "</body>\n</html>\n");
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
  err_no = -1;

 done:
  free(boundaryPattern);
  free(mp_arg);
  return err_no;
}

void ox_cbs_index(evhtp_request_t *req, void *arg)
{
  evbuffer_add_printf(req->buffer_out, "<html><body><h1>OX works!</h1></body></html>");
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
  evhtp_send_reply(req, EVHTP_RES_OK);
}

void _image_post(evhtp_request_t *req)
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
    err_no = _binary_parse(req, content_type, address, buff, post_size);
  }
  else {
    ret_json = 0;
    err_no = _multipart_parse(req, content_type, address, buff, post_size);
  }
  if(err_no != -1) {
    goto err;
  }
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============ox_cbs_post() DONE!===============");
  goto done;

 forbidden:
  _jreturn(req, err_no, NULL, 0);
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
    _jreturn(req, err_no, NULL, 0);
  }
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============ox_cbs_post() ERROR!===============");

 done:
  free(buff);
}

void _image_get(evhtp_request_t *req)
{
  char *md5 = NULL;
  char *fmt = NULL;
  char *type = NULL;
  char *buff = NULL;
  size_t len;
  ox_req_t *ox_req = NULL;

  evhtp_connection_t *ev_conn = evhtp_request_get_connection(req);
  struct sockaddr *saddr = ev_conn->saddr;
  struct sockaddr_in *ss = (struct sockaddr_in *)saddr;
  char address[16];

  const char *xff_address = evhtp_header_find(req->headers_in, "X-Forwarded-For");
  if(xff_address) {
    inet_aton(xff_address, &ss->sin_addr);
  }
  else {
    inet_aton("0.0.0.0", &ss->sin_addr);
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
  if((strlen(uri) == 6 || strlen(uri) == 7) &&
     uri[0]=='/' && uri[1]=='i' && uri[2]=='m' && uri[3]=='a' && uri[4]=='g' && uri[5]=='e') {
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
    LOG_PRINT(LOG_DEBUG, "============_image_get() DONE!===============");
    LOG_PRINT(LOG_INFO, "%s succ root page", address);
    goto done;
  }

  if(strstr(uri, "favicon.ico")) {
    LOG_PRINT(LOG_DEBUG, "favicon.ico Request, Denied.");
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
    ox_headers_add(req, vars.headers);
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
    ox_strlcpy(md5, uri+1+5+1, md5_len);//这里处理URL
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

  evthr_t *thread = _get_request_thr(req);
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
  ox_req = (ox_req_t *)malloc(sizeof(ox_req_t));
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
    get_img_rst = ox_db_get_mode(ox_req, req); //db
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
  ox_headers_add(req, vars.headers);
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

void ox_cbs_image(evhtp_request_t *req, void *arg)
{

  int req_method = evhtp_request_get_method(req);
  if(req_method >= 16) {
    req_method = 16;
  }

  LOG_PRINT(LOG_DEBUG, "Method: %d", req_method);
  if(strcmp(method_strmap[req_method], "POST") == 0) {
    _image_post(req);
    return;
  }
  else if(strcmp(method_strmap[req_method], "GET") == 0) {
    _image_get(req);
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

void _doc_post(evhtp_request_t *req)
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
    err_no = _binary_parse_doc(req, content_type, address, buff, post_size);
  }
  else {
    ret_json = 0;
    err_no = _multipart_parse(req, content_type, address, buff, post_size);
  }
  if(err_no != -1) {
    goto err;
  }
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============ox_cbs_post() DONE!===============");
  goto done;

 forbidden:
  _jreturn(req, err_no, NULL, 0);
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
    _jreturn(req, err_no, NULL, 0);
  }
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============ox_cbs_post() ERROR!===============");

 done:
  free(buff);
}

void _doc_get(evhtp_request_t *req)
{
  char *md5 = NULL;
  char *fmt = NULL;
  char *type = NULL;
  char *buff = NULL;
  char *fname = NULL;
  size_t len;
  ox_req_t *ox_req = NULL;

  evhtp_connection_t *ev_conn = evhtp_request_get_connection(req);
  struct sockaddr *saddr = ev_conn->saddr;
  struct sockaddr_in *ss = (struct sockaddr_in *)saddr;
  char address[16];

  const char *xff_address = evhtp_header_find(req->headers_in, "X-Forwarded-For");
  if(xff_address) {
    inet_aton(xff_address, &ss->sin_addr);
  }
  else {
    inet_aton("0.0.0.0", &ss->sin_addr);
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
     uri[0]=='/' && uri[1]=='d' && uri[2]=='o' && uri[3]=='c') {
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
    LOG_PRINT(LOG_DEBUG, "============_image_get() DONE!===============");
    LOG_PRINT(LOG_INFO, "%s succ root page", address);
    goto done;
  }

  if(strstr(uri, "favicon.ico")) {
    LOG_PRINT(LOG_DEBUG, "favicon.ico Request, Denied.");
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
    ox_headers_add(req, vars.headers);
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

  evthr_t *thread = _get_request_thr(req);
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
  }

  ox_req = (ox_req_t *)calloc(sizeof(ox_req_t), sizeof(ox_req_t));
  ox_req->md5 = md5;
  ox_req->thr_arg = thr_arg;
  ox_req->fname = fname;

  int get_doc_rst = -1;

  // storage setting
  if (vars.mode == 1) {
    get_doc_rst = ox_doc_get(ox_req, req);
  }
  else {
    get_doc_rst = ox_db_get_doc_mode(ox_req, req);
  }

  if(get_doc_rst == -1) {
    LOG_PRINT(LOG_DEBUG, "OX Requset Get Doc[MD5: %s] Failed!", md5);
    goto err;
  }

  len = evbuffer_get_length(req->buffer_out);
  LOG_PRINT(LOG_DEBUG, "get buffer length: %d", len);

  LOG_PRINT(LOG_DEBUG, "Got the File!");
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  //todo libmagic处理mime
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "application/octet-stream", 0, 0));
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Disposition", fname, 0, 0));

  ox_headers_add(req, vars.headers);
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
  free(buff);
  free(fname);
}

void ox_cbs_doc(evhtp_request_t *req, void *arg)
{

  int req_method = evhtp_request_get_method(req);
  if(req_method >= 16) {
    req_method = 16;
  }

  LOG_PRINT(LOG_DEBUG, "Method: %d", req_method);
  if(strcmp(method_strmap[req_method], "POST") == 0) {
    _doc_post(req);
    return;
  }
  else if(strcmp(method_strmap[req_method], "GET") == 0) {
    _doc_get(req);
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
  LOG_PRINT(LOG_DEBUG, "============ox_cbs_doc() ERROR!===============");

}


void _mov_post(evhtp_request_t *req)
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
    LOG_PRINT(LOG_DEBUG, "Movie size is zero!");
    LOG_PRINT(LOG_ERROR, "%s fail post empty", address);
    err_no = 5;
    goto err;
  }
  if(post_size > vars.max_size_mov) {
    LOG_PRINT(LOG_DEBUG, "movie size too large!");
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
    err_no = _binary_parse_mov(req, content_type, address, buff, post_size);
  }
  else {
    ret_json = 0;
    err_no = _multipart_parse(req, content_type, address, buff, post_size);
  }
  if(err_no != -1) {
    goto err;
  }
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============ox_cbs_post() DONE!===============");
  goto done;

 forbidden:
  _jreturn(req, err_no, NULL, 0);
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
    _jreturn(req, err_no, NULL, 0);
  }
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  evhtp_send_reply(req, EVHTP_RES_OK);
  LOG_PRINT(LOG_DEBUG, "============ox_cbs_post() ERROR!===============");

 done:
  free(buff);
}

void _mov_get(evhtp_request_t *req)
{
  char *md5 = NULL;
  char *fmt = NULL;
  char *type = NULL;
  char *buff = NULL;
  char *fname = NULL;
  size_t len;
  ox_req_t *ox_req = NULL;

  evhtp_connection_t *ev_conn = evhtp_request_get_connection(req);
  struct sockaddr *saddr = ev_conn->saddr;
  struct sockaddr_in *ss = (struct sockaddr_in *)saddr;
  char address[16];

  const char *xff_address = evhtp_header_find(req->headers_in, "X-Forwarded-For");
  if(xff_address) {
    inet_aton(xff_address, &ss->sin_addr);
  }
  else {
    inet_aton("0.0.0.0", &ss->sin_addr);
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
  if((strlen(uri) == 6 || strlen(uri) == 7) &&
     uri[0]=='/' && uri[1]=='v' && uri[2]=='i' && uri[3]=='d' && uri[4]=='e' && uri[5]=='o') {
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
    LOG_PRINT(LOG_DEBUG, "============_image_get() DONE!===============");
    LOG_PRINT(LOG_INFO, "%s succ root page", address);
    goto done;
  }

  if(strstr(uri, "favicon.ico")) {
    LOG_PRINT(LOG_DEBUG, "favicon.ico Request, Denied.");
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
    evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
    ox_headers_add(req, vars.headers);
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
    ox_strlcpy(md5, uri+1+5+1, md5_len);//这里处理URL
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

  evthr_t *thread = _get_request_thr(req);
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
  }

  ox_req = (ox_req_t *)calloc(sizeof(ox_req_t), sizeof(ox_req_t));
  ox_req->md5 = md5;
  ox_req->thr_arg = thr_arg;
  ox_req->fname = fname;

  int get_mov_rst = -1;

  // storage setting
  /* if (vars.mode == 1) { */
  get_mov_rst = ox_mov_get(ox_req, req);
  /* } */
  /* else { */
  /*   get_mov_rst = ox_db_get_mov_mode(ox_req, req); */
  /* } */

  if(get_mov_rst == -1) {
    LOG_PRINT(LOG_DEBUG, "OX Requset Get Movie [MD5: %s] Failed!", md5);
    goto err;
  }

  len = evbuffer_get_length(req->buffer_out);
  LOG_PRINT(LOG_DEBUG, "get buffer length: %d", len);

  LOG_PRINT(LOG_DEBUG, "Got the File!");
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Server", vars.server_name, 0, 1));
  //todo libmagic处理mime
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Type", "application/octet-stream", 0, 0));
  evhtp_headers_add_header(req->headers_out, evhtp_header_new("Content-Disposition", fname, 0, 0));

  ox_headers_add(req, vars.headers);
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
  free(buff);
  free(fname);
}

void ox_cbs_mov(evhtp_request_t *req, void *arg)
{

  int req_method = evhtp_request_get_method(req);
  if(req_method >= 16) {
    req_method = 16;
  }

  LOG_PRINT(LOG_DEBUG, "Method: %d", req_method);
  if(strcmp(method_strmap[req_method], "POST") == 0) {
    _mov_post(req);
    return;
  }
  else if(strcmp(method_strmap[req_method], "GET") == 0) {
    _mov_get(req);
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
  LOG_PRINT(LOG_DEBUG, "============ox_cbs_mov() ERROR!===============");

}
