# SMTP
A simple SMTP mail server using Socket API
# 1. 概述
使用Socket API 编写一个 SMTP 邮件服务器程序，该程序使用SMTP接收来自邮件客户端（如 Foxmail、 outlook）的邮件，并使用SMTP转发到实际的接收邮件服务器
的用户邮箱 （如 @163.com、 @bupt.edu.cn等）。
# 2. 功能实现
* 作为SMTP服务器，接收邮件客户端程序的TCP连接请求，接收SMTP命令和邮件数据，将邮件保存在文件中。
* 作为SMTP客户端，建立到实际邮件服务器的 TCP 连接，发送 SMTP 命令，将保存的邮件发送给实际邮件服务器。
* 支持一封邮件多个接收者，要求接收者属于不同的域 。
* 提供发件人和收件人Email地址格式检查功能 。
* 支持 SSL安全连接功能。
# 3. 主要功能模块
* getfile模块：接收邮件内容存到指定的文件中
* change_time模块：获取时间戳用于创建日志
* Base64加密模块：加密邮件内容用于发送
* Send模块：用于发送邮件
* opensocketrmail模块：打开 与客户端的 socket连接，
* Sslmail模块：实现以 ssl方式发送邮件
* Receive模块：接收 foxmail来的邮件及内容
* mail模块：实现不通过 ssl加密的邮件的转发
