在linux上使用bpftrace

bpftrace [optional] 文件名
bpftrace [optional] -e 'process-code'
当文件名是-的时候，bpftrace将从stdin读取程序代码
程序会持续运行，直到按下 Ctrl-C 或exit调用某个函数。程序退出时，所有已填充的地图都会被打印出来

跟踪调用sleep的进程
```bash
bpftrace -e 'kprobe:do_nanosleep { printf("%d sleeping\n", pid);}'
```

列出带有sleep的所有探测器
```bash
 bpftrace -l '*sleep*'
```

查看所有探测器
```bash
bpftrace -l 'kprobe:*'
bpftrace -l 't:syscalls:*openat*'
bpftrace -l -e 'tracepoint:xdp:mem_* { exit(); }'
bpftrace -l 'kprobe:tcp*'
bpftrace -l 'uprobe:*'
```
-v可以指定详细标志（ ）来检查args支持它的提供程序的参数（）：
```bash
bpftrace -l 'tracepoint:xdp:mem_connect' -v
```

reference:
* https://github.com/bpftrace/bpftrace/blob/master/man/adoc/bpftrace.adoc
* https://eunomia.dev/tutorials/bpftrace-tutorial/

