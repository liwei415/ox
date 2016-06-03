#include "ox_cbs.h"

static const char *post_error_list[] = {
  "Internal error.",
  "File type not support.",
  "Request method error.",
  "Access error.",
  "Request body parse error.",
  "Content-Length error.",
  "Content-Type error.",
  "File too large.",
  "Request url illegal.",
  "Image not existed.",
  "Delete resource failed.",
  "Wrong input params.",
  "Wrong Json Node."
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
    end = (end) ? end : hdr + hdr_len;
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

int ox_cbs_headers_add(evhtp_request_t *req, ox_cbs_headers_conf_t *hcf)
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

evthr_t *ox_cbs_get_request_thr(evhtp_request_t *request)
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

int ox_cbs_jreturn(evhtp_request_t *req, int err_no, const char *md5sum, int post_size)
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

int ox_cbs_multipart_parse(evhtp_request_t *req, const char *content_type, const char *address, const char *buff, int post_size)
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

  evthr_t *thread = ox_cbs_get_request_thr(req);
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
