
监控敏感文件比如/etc/passwd, 审计日志的读取，修改，删除】
#[kprobe(function = "vfs_read")]



监控进程被kill的安全检查函数
#[kprobe(function = "security_task_kill")]


监控网络连接比如tcp三次握手，监控进程发起的网络连接，统计应用的网络连接行为，检测异常连接
#[kprobe(function = "__sys_connect")]
比如我们需要监控
连接的源地址、目标地址（IP、端口）
进程信息（发起连接的进程名、PID、UID 等）
连接是否成功（通过返回值判断）
只要是通过 connect() 系统调用发起的连接（包括 TCP、UDP、部分 UNIX 域），都会被采集到。