#ifndef _OX_GM_
#define _OX_GM_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <string.h>
#include <wand/magick_wand.h>

#include "ox_log.h"
#include "ox_common.h"

int ox_gm_convert(MagickWand *im, ox_req_img_t *req);

#endif
