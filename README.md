![LOGO](flyingsocks.png)
### flyingsocks 路由器客户端
flyingsocks路由器客户端部署在Linux系统的路由器，以便连接到该路由器的设备能够无缝使用代理服务。<br>
相比桌面客户端，路由器客户端的优势主要是实现透明代理。

在使用路由器客户端前，需要事先部署好服务端。 桌面客户端及其服务端的仓库链接：https://github.com/abc123lzf/flyingsocks <br>

### 路由器配置要求
- 使用Linux内核的操作系统
- ARMv7或者ARMv8架构的路由器（x86软路由也可）
- 32MB以上的空闲内存，正常使用Web网页等轻度代理需求时内存占用一般不超过10MB；
- 10MB的剩余存储空间；
- 支持SSH连接路由器；
- 包含iptables，ipset命令（部分官方系统的路由器没有ipset，可以通过刷官改系统或者梅林系统解决）。

### 依赖库
- libevent v2.1.12，GitHub链接 https://github.com/libevent/libevent
- libconfuse v3.3，GitHub链接 https://github.com/libconfuse/libconfuse
- libssl / libcrypto，一般系统自带
- libdl，一般系统自带

### 编译安装
1. 项目路径下新建文件夹build
```
mkdir build
cd build
```
2. CMake生成Makefile，然后make
```
cmake ..
make
```
3. 进入项目路径下的target文件夹，按照配置说明进行配置
4. 执行whitelist-init.sh脚本，然后执行生成的ipset-build.sh脚本，以便初始化IP白名单
5. 配置环境变量为SERVER_ADDRESS，其值为服务器IPv4地址
6. 执行startup.sh脚本启动应用程序，当需要关闭时，使用stop.sh脚本

### 配置说明
1. 日志配置
日志配置存储在文件conf/logger.conf中，包含三个配置项：<br>
    - enable-stdout，是否输出日志信息到标准输出流，true或者false；
    - file-path，日志文件输出路径（不包括日志文件，例如当值为/var/log时，日志输出到文件/var/log/fs-client.log）；
    - logger-level，日志等级，可选为INFO、WARN、ERROR或者NONE（不输出日志）。
2. 本地代理服务配置
    - proxy-auto-mode，PAC模式，0表示
    - enable-tcp-proxy，是否开启TCP透明代理，true或者false；
    - proxy-tcp-port，TCP透明代理端口，默认17020
    - dns-service-port，DNS服务端口，一般为53。
3. 代理服务器配置
   - hostname，服务器域名或者IP地址；
   - port，服务器代理服务端口号；
   - encrypt-type，服务器加密方式，none或者openssl，使用SSL时，需要保证服务器的证书为CA机构签发的证书，不能为自签证书；
   - auth-type，认证方式，simple或者user，对应于简单认证和用户认证
   - auth-arg，认证参数，当auth-type为simple时，直接填写密码即可，当auth-type为user时，需要填写用户名和密码，例如用户名和密码分别为admin和123456，那么其值为{admin,123456}
   