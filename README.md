## Overview
OX is a image/file/video server, written by pure C.

## Required Dependencies
* [libevhtp](https://github.com/ellzey/libevhtp/)
* Centos 7, install ImageMagick with: yum install GraphicsMagick-devel(epel)
* Centos 7, install libmagic with: yum install file-devel(base)

## Building
* cd ox
* ./rebuild

## Run
1. copy "ox", "conf/ox.lua", "conf/process.lua" to your project dir
2. config "ox.lua" and "process.lua"
3. run with "./ox"

## Test
* 图片
1. upload: curl -H "Content-Type:jpeg" --data-binary @xx.jpg "http://127.0.0.1:xxx/img"
2. download: http://127.0.0.1:xxx/img/(md5)?w=0&h=0&g=0&x=0&y=0&r=0&q=85&f=jpg

* 文档
1. upload: curl -H "Content-Type:text" --data-binary @xx.txt "http://127.0.0.1:xxx/doc"
2. download: http://127.0.0.1:xxx/doc/(md5)?n=xx.txt

* 视频
1. upload: curl -H "Content-Type:mov" --data-binary @xx.mov "http://127.0.0.1:xxx/mov"
2. download: http://127.0.0.1:xxx/mov/(md5)?n=xx.mov
