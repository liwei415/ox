#include "ox_utils.h"

int ox_file_type(const char *filename, char *type)
{
  char *flag, *tmp;
  if((flag = strchr(filename, '.')) == 0) {
    LOG_PRINT(LOG_DEBUG, "FileName [%s] Has No '.' in It.", filename);
    return -1;
  }

  while((tmp = strchr(flag + 1, '.')) != 0) {
    flag = tmp;
  }
  flag++;
  ox_strlcpy(type, flag, 32);
  return 1;
}

int ox_isfile(const char *filename)
{
  struct stat st;
  if(stat(filename, &st) < 0) {
    LOG_PRINT(LOG_DEBUG, "File[%s] is Not Existed!", filename);
    return -1;
  }
  if(S_ISREG(st.st_mode)) {
    LOG_PRINT(LOG_DEBUG, "File[%s] is A File.", filename);
    return 1;
  }
  return -1;
}

int ox_isimg(const char *filename)
{
  int isimg = -1;

  lua_getglobal(vars.L, "is_img");
  lua_pushstring(vars.L, filename);
  if(lua_pcall(vars.L, 1, 1, 0) != 0) {
    LOG_PRINT(LOG_WARNING, "lua is_img() failed!");
    return isimg;
  }
  isimg = (int)lua_tonumber(vars.L, -1);
  lua_pop(vars.L, 1);

  return isimg;
}

int ox_isdir(const char *path)
{
  struct stat st;
  if(stat(path, &st) < 0) {
    LOG_PRINT(LOG_DEBUG, "Path[%s] is Not Existed!", path);
    return -1;
  }
  if(S_ISDIR(st.st_mode)) {
    LOG_PRINT(LOG_DEBUG, "Path[%s] is A Dir.", path);
    return 1;
  }
  else {
    return -1;
  }
}

int ox_mkdir(const char *path)
{
  if(access(path, 0) == -1) {
    int status = mkdir(path, 0755);
    if(status == -1) {
      LOG_PRINT(LOG_DEBUG, "mkdir[%s] Failed!", path);
      return -1;
    }
    LOG_PRINT(LOG_DEBUG, "mkdir[%s] sucessfully!", path);
    return 1;
  }
  else {
    LOG_PRINT(LOG_DEBUG, "Path[%s] is Existed!", path);
    return -1;
  }
}

int ox_mkdirs(const char *dir)
{
  char tmp[256];
  ox_strlcpy(tmp, dir, sizeof(tmp));
  int i, len = strlen(tmp);
  if(tmp[len-1] != '/') {
    ox_strlcat(tmp, "/", sizeof(tmp));
  }

  len = strlen(tmp);
  for(i=1; i<len; i++) {
    if(tmp[i] == '/') {
      tmp[i] = 0;
      if(access(tmp, 0) != 0) {
        if(mkdir(tmp, 0755) == -1) {
          fprintf(stderr, "ox_mkdirs: tmp=%s\n", tmp);
          return -1;
        }
      }
      tmp[i] = '/';
    }
  }
  return 1;
}

int ox_mkdirf(const char *filename)
{
  int ret = 1;
  if (access(filename, 0) == 0) {
    return ret;
  }
  size_t len = strlen(filename);
  char str[256];
  ox_strlcpy(str, filename, len);
  str[len] = '\0';
  char *end = str;
  char *start = strchr(end, '/');
  while (start) {
    end = start + 1;
    start = strchr(end, '/');
  }
  if (end != str) {
    str[end-str] = '\0';
    ret = ox_mkdirs(str);
  }
  return ret;
}

int ox_ismd5(char *s)
{
  int rst = -1;
  int i = 0;
  for (; (s[i]>='0' && s[i]<='9') || (s[i]>='a' && s[i]<='f') || (s[i]>='A' && s[i]<='F'); ++i) {
  }

  if(i == 32 && s[i] == '\0') {
    rst = 1;
  }
  return rst;
}

int ox_strhash(const char *str)
{
    char c[4];
    ox_strlcpy(c, str, 4);
    //LOG_PRINT(LOG_DEBUG, "str = %s.", c);
    //int d = htoi(c);
    int d = strtol(c, NULL, 16);
    //LOG_PRINT(LOG_DEBUG, "str(3)_to_d = %d.", d);
    d = d / 2;
    //LOG_PRINT(LOG_DEBUG, "str(3)/4 = %d.", d);
    return d;
}

int ox_genkey(char *key, char *md5, ...)
{
  snprintf(key, CACHE_KEY_SIZE, "%s", md5);
  va_list arg_ptr;
  va_start(arg_ptr, md5);
  int argc = va_arg(arg_ptr, int);
  char tmp[CACHE_KEY_SIZE];
  //LOG_PRINT(LOG_DEBUG, "argc: %d", argc);
  if(argc > 1) {
    int i, argv;
    for(i = 0; i < argc-1; i++) {
      argv = va_arg(arg_ptr, int);
      snprintf(tmp, CACHE_KEY_SIZE, "%s:%d", key, argv);
      snprintf(key, CACHE_KEY_SIZE, "%s", tmp);
      //LOG_PRINT(LOG_DEBUG, "arg[%d]: %d", i, argv);
    }
    char *fmt = va_arg(arg_ptr, char *);
    snprintf(tmp, CACHE_KEY_SIZE, "%s:%s", key, fmt);
    snprintf(key, CACHE_KEY_SIZE, "%s", tmp);
  }
  va_end(arg_ptr);
  LOG_PRINT(LOG_DEBUG, "key: %s", key);

  return 1;
}
