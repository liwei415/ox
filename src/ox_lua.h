#ifndef _OX_LUA_
#define _OX_LUA_

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "ox_log.h"
#include "ox_common.h"

typedef struct lua_arg_s lua_arg_t;
struct lua_arg_s {
  MagickWand *img;
  char *trans_type;
  int lua_ret;
};

int ox_lua_convert(MagickWand *im, ox_req_t *req);

#endif
