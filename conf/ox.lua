--ox server config

--是否守护进程运行
is_daemon = 0

--server config
--绑定IP
ip = '0.0.0.0'
--端口
port = 9527
--运行线程数(CPU数)
thread_num = 2
backlog_num = 1024
max_keepalives  = 1
--retry = 3
system = io.popen('uname -sn'):read('*l')
pwd = io.popen('pwd'):read('*l')

--header config
--返回时所带的HTTP header
headers = 'Cache-Control:max-age=7776000'
--是否启用etag缓存
etag = 1

--access config
--support mask rules like 'allow 10.1.121.138/24'
--NOTE: remove rule can improve performance
--上传接口的IP控制权限，将权限规则注释掉可以提升服务器处理能力，下同
upload_rule = 'allow 0.0.0.0; 192.168.11.0/24; 192.168.1.111'
--下载接口的IP控制权限(此ip可绕开锁)
download_rule = 'allow 192.168.1.111'
--删除接口的IP控制权限
--delete_rule = 'allow all'

--cache config
--是否启用memcached
cache = 0
--缓存服务器IP
memc_ip = '127.0.0.1'
--缓存服务器端口
memc_port = 11211

--log config
--log_level output specified level of log to logfile
--[[
LOG_FATAL 0 System is unusable
LOG_ALERT 1 Action must be taken immediately
LOG_CRIT 2 Critical conditions
LOG_ERROR 3 Error conditions
LOG_WARNING 4 Warning conditions
LOG_NOTICE 5 Normal, but significant
LOG_INFO 6 Information
LOG_DEBUG 7 DEBUG message
]]
--输出log级别
log_level = 7
--输出log路径
log_path = pwd .. '/ox.log'

--htdoc config
--image process config
--禁用URL图片处理
disable_args = 0
--禁用lua脚本图片处理
disable_type = 0
--禁用图片放大
disable_zoom_up = 0
--lua process script
--lua脚本文件路径
script_name = pwd .. '/process.lua'

--format value: 'none' for original or other format names
--默认保存新图的格式，字符串'none'表示以原有格式保存，或者是期望使用的格式名
format = 'jpg'
--quality value: 1~100(default: 75)
--默认保存新图的质量
quality = 75

--storage config
--ox support 3 ways for storage images
--value 1 is for local disk storage;
--value 2 is for memcached protocol storage like beansdb;
--value 3 is for redis protocol storage like SSDB.
--存储后端类型，1为本地存储, 3为redis协议后端如SSDB
mode = 3
--save_new value: 0.don't save any 1.save all 2.only save types in lua script
--新文件是否存储，0为不存储，1为全都存储，2为只存储lua脚本产生的新图
save_new = 2
--上传大小限制，默认5MB
max_size_img = 100*1024*1024
max_size_doc = 100*1024*1024
max_size_mov = 100*1024*1024

--允许上传类型列表
allowed_type_img = {'image/jpeg', 'image/jpg', 'image/png', 'image/gif'}
allowed_type_doc = {'text/plain', 'application/pdf'}
allowed_type_mov = {'video/mp4'}

--mode[1]: local disk mode
--本地存储时的存储路径
img_path = pwd .. '/img'
doc_path = pwd .. '/doc'
mov_path = pwd .. '/mov'

--mode[3]: ssdb mode
--SSDB服务器IP
ssdb_ip = '127.0.0.1'
--SSDB服务器端口
ssdb_port = 8888

--lua conf functions
--部分与配置有关的函数在lua中实现，对性能影响不大
function is_img(type_name)
    local found = -1
    for _, allowed in pairs(allowed_type_img) do
        if string.lower(type_name) == allowed then
            found = 1
            break
        end
    end
    return found
end

function is_doc(type_name)
    local found = -1
    for _, allowed in pairs(allowed_type_doc) do
        if string.lower(type_name) == allowed then
            found = 1
            break
        end
    end
    return found
end

function is_mov(type_name)
    local found = -1
    for _, allowed in pairs(allowed_type_mov) do
        if string.lower(type_name) == allowed then
            found = 1
            break
        end
    end
    return found
end

