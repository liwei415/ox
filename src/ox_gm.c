#include <wand/magick_wand.h>

#include "ox_gm.h"

static int _proportion(MagickWand *im, int p_type, int cols, int rows);
static int _crop(MagickWand *im, int x, int y, int cols, int rows);
int ox_gm_convert(MagickWand *im, ox_req_t *req);

static int _proportion(MagickWand *im, int p_type, int cols, int rows)
{
  int ret = -1;
  unsigned long im_cols = MagickGetImageWidth(im);
  unsigned long im_rows = MagickGetImageHeight(im);

  if (vars.disable_zoom_up == 1) {
    if (p_type == 3) {
      cols = cols > 100 ? 100 : cols;
      rows = rows > 100 ? 100 : rows;
    }
    else {
      cols = cols > im_cols ? im_cols : cols;
      rows = rows > im_rows ? im_rows : rows;
    }
  }

  if (p_type == 1) {
    if (cols == 0 || rows == 0) {
      if (cols > 0) {
        rows = (uint32_t)round(((double)cols / im_cols) * im_rows);
      }
      else {
        cols = (uint32_t)round(((double)rows / im_rows) * im_cols);
      }
      LOG_PRINT(LOG_DEBUG, "p=1, wi_scale(im, %d, %d)", cols, rows);
      ret = MagickResizeImage(im, cols, rows, UndefinedFilter, 1.0);
      //ret = MagickScaleImage(im, cols, rows);
    }
    else {
      uint32_t x = 0, y = 0, s_cols, s_rows;
      double cols_rate = (double)cols / im_cols;
      double rows_rate = (double)rows / im_rows;

      if (cols_rate > rows_rate) {
        s_cols = cols;
        s_rows = (uint32_t)round(cols_rate * im_rows);
        y = (uint32_t)floor((s_rows - rows) / 2.0);
      }
      else {
        s_cols = (uint32_t)round(rows_rate * im_cols);
        s_rows = rows;
        x = (uint32_t)floor((s_cols - cols) / 2.0);
      }
      LOG_PRINT(LOG_DEBUG, "p=2, wi_scale(im, %d, %d)", s_cols, s_rows);
      ret = MagickResizeImage(im, s_cols, s_rows, UndefinedFilter, 1.0);
      //ret = MagickScaleImage(im, s_cols, s_rows);

      LOG_PRINT(LOG_DEBUG, "p=2, wi_crop(im, %d, %d, %d, %d)", x, y, cols, rows);
      ret = MagickCropImage(im, cols, rows, x, y);
    }
  }
  else if (p_type == 2) {
    uint32_t x, y;
    x = (uint32_t)floor((im_cols - cols) / 2.0);
    y = (uint32_t)floor((im_rows - rows) / 2.0);
    LOG_PRINT(LOG_DEBUG, "p=2, wi_crop(im, %d, %d, %d, %d)", x, y, cols, rows);
    ret = MagickCropImage(im, cols, rows, x, y);
  }
  else if (p_type == 3) {
    if (cols == 0 || rows == 0) {
      int rate = cols > 0 ? cols : rows;
      rows = (uint32_t)round(im_rows * (double)rate / 100);
      cols = (uint32_t)round(im_cols * (double)rate / 100);
      LOG_PRINT(LOG_DEBUG, "p=3, wi_scale(im, %d, %d)", cols, rows);
      ret = MagickResizeImage(im, cols, rows, UndefinedFilter, 1.0);
      //ret = MagickScaleImage(im, cols, rows);
    }
    else {
      rows = (uint32_t)round(im_rows * (double)rows / 100);
      cols = (uint32_t)round(im_cols * (double)cols / 100);
      LOG_PRINT(LOG_DEBUG, "p=3, wi_scale(im, %d, %d)", cols, rows);
      ret = MagickResizeImage(im, cols, rows, UndefinedFilter, 1.0);
      //ret = MagickScaleImage(im, cols, rows);
    }
  }
  else if (p_type == 0) {
    LOG_PRINT(LOG_DEBUG, "p=0, wi_scale(im, %d, %d)", cols, rows);
    ret = MagickResizeImage(im, cols, rows, UndefinedFilter, 1.0);
    //ret = MagickScaleImage(im, cols, rows);
  }
  else if (p_type == 4) {
    double rate = 1.0;
    if (cols == 0 || rows == 0) {
      rate = cols > 0 ? (double)cols / im_cols : (double)rows / im_rows;
    }
    else {
      double rate_col = (double)cols / im_cols;
      double rate_row = (double)rows / im_rows;
      rate = rate_col < rate_row ? rate_col : rate_row;
    }
    cols = (uint32_t)round(im_cols * rate);
    rows = (uint32_t)round(im_rows * rate);
    LOG_PRINT(LOG_DEBUG, "p=4, wi_scale(im, %d, %d)", cols, rows);
    ret = MagickResizeImage(im, cols, rows, UndefinedFilter, 1.0);
  }

  return ret;
}

static int _crop(MagickWand *im, int x, int y, int cols, int rows)
{
  int ret = -1;
  unsigned long im_cols = MagickGetImageWidth(im);
  unsigned long im_rows = MagickGetImageHeight(im);
  if (x < 0) {
    x = 0;
  }
  if (y < 0) {
    y = 0;
  }
  if (x >= im_cols || y >= im_rows) {
    return -1;
  }
  if (cols == 0 || im_cols < x + cols) {
    cols = im_cols - x;
  }
  if (rows == 0 || im_rows < y + rows) {
    rows = im_rows - y;
  }
  LOG_PRINT(LOG_DEBUG, "wi_crop(im, %d, %d, %d, %d)", x, y, cols, rows);
  ret = MagickCropImage(im, cols, rows, x, y);
  return ret;
}

int ox_gm_convert(MagickWand *im, ox_req_t *req)
{
  int result = 1, ret = -1;

  MagickResetIterator(im);
  // MagickSetImageOrientation(im, TopLeftOrientation);

  int x = req->x, y = req->y, cols = req->width, rows = req->height;
  if (!(cols == 0 && rows == 0)) {
    /* crop and scale */
    if (x == -1 && y == -1) {
      LOG_PRINT(LOG_DEBUG, "proportion(im, %d, %d, %d)", req->proportion, cols, rows);
      ret = _proportion(im, req->proportion, cols, rows);
      if (ret != MagickTrue) {
        return -1;
      }
    }
    else {
      LOG_PRINT(LOG_DEBUG, "crop(im, %d, %d, %d, %d)", x, y, cols, rows);
      ret = _crop(im, x, y, cols, rows);
      if (ret != MagickTrue) {
        return -1;
      }
    }
  }

  /* rotate image */
  if (req->rotate != 0) {
    LOG_PRINT(LOG_DEBUG, "wi_rotate(im, %d)", req->rotate);
    PixelWand *background = NewPixelWand();
    if (background == NULL) return -1;
    ret = PixelSetColor(background, "white");
    if (ret != MagickTrue) {
      DestroyPixelWand(background);
      return -1;
    }
    ret = MagickRotateImage(im, background, req->rotate);
    LOG_PRINT(LOG_DEBUG, "rotate() ret = %d", ret);
    DestroyPixelWand(background);
    if (ret != MagickTrue) {
      return -1;
    }
  }

  /* set gray */
  if (req->gray == 1) {
    LOG_PRINT(LOG_DEBUG, "wi_gray(im)");
    //several ways to grayscale an image:
    //ret = MagickSetImageColorspace(im, GRAYColorspace);
    //ret = MagickQuantizeImage(im, 256, GRAYColorspace, 0, MagickFalse, MagickFalse);
    //ret = MagickSeparateImageChannel(im, GrayChannel);
    ret = MagickSetImageType(im, GrayscaleType);
    LOG_PRINT(LOG_DEBUG, "gray() ret = %d", ret);
    if (ret != MagickTrue) {
      return -1;
    }
  }

  /* set quality */
  /*
    int quality = 100;
    int im_quality = MagickGetImageCompressionQuality(im);
    im_quality = (im_quality == 0 ? 100 : im_quality);
    LOG_PRINT(LOG_DEBUG, "wi_quality = %d", im_quality);
    quality = req->quality < im_quality ? req->quality : im_quality;
  */
  LOG_PRINT(LOG_DEBUG, "wi_set_quality(im, %d)", req->quality);
  ret = MagickSetCompressionQuality(im, req->quality);
  // ret = MagickSetImageCompressionQuality(im, req->quality);
  if (ret != MagickTrue) {
    return -1;
  }

  /* set format */
  if (strncmp(req->fmt, "none", 4) != 0) {
    LOG_PRINT(LOG_DEBUG, "wi_set_format(im, %s)", req->fmt);
    ret = MagickSetImageFormat(im, req->fmt);
    if (ret != MagickTrue) {
      return -1;
    }
  }

  LOG_PRINT(LOG_DEBUG, "convert(im, req) %d", result);
  return result;
}
