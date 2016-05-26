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

## TODO
* post多个资源实现


## Log
+++++++++++++++++++++++++++++++++20160526 更新日志++++++++++++++++++++++++++++++++++++++  
* 修复加锁时文档，视频判断lock存在的问题
* 测试通过

+++++++++++++++++++++++++++++++++20160525 更新日志++++++++++++++++++++++++++++++++++++++  
* 获得资源get处处理锁逻辑
* 解锁unlock逻辑实现

+++++++++++++++++++++++++++++++++20160524 更新日志++++++++++++++++++++++++++++++++++++++  
* 增加资源加锁操作接口（get，每次对单个资源处理）
* 在获得资源接口（get处）处理锁逻辑
* 重新设计api：
  * delete在一些地方使用不友好，故delete做为二级资源定位出现：/img/del
  * post接收数组参数处理多个资源
  * post的url全部复数形式
  * lock/unlock暂时方在资源后面二级出现。比如/img/lock或者/img/unlock
* cbs重新设计，单个功能独立function

+++++++++++++++++++++++++++++++++20160523 更新日志++++++++++++++++++++++++++++++++++++++  
* 增加资源的删除操作接口（get，每次对单个资源处理）
* 新增ox_cbs_img.c,ox_cbs_img.h文件调整代码结构
* 新增ox_cbs_doc.c,ox_cbs_doc.h文件调整代码结构
* 新增ox_cbs_mov.c,ox_cbs_mov.h文件调整代码结构
* 修复一个疑似内存泄露bug（无free）
