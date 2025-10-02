# 在linux上使用bpftrace

bpftrace [optional] 文件名
bpftrace [optional] -e 'process-code'
当文件名是-的时候，bpftrace将从stdin读取程序代码
程序会持续运行，直到按下 Ctrl-C 或exit调用某个函数。程序退出时，所有已填充的地图都会被打印出来

## 跟踪调用sleep的进程
```bash
bpftrace -e 'kprobe:do_nanosleep { printf("%d sleeping\n", pid);}'
```

## 列出带有sleep的所有探测器
```bash
 bpftrace -l '*sleep*'
```

## 查看所有探测器
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

## 打印hello world

```bash
bpftrace -e 'BEGIN { printf("hello world\n")} '
```

## 跟踪文件打开
```bash
bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(args.filename)); }'
```
comm是一个内置变量，包含当前进程的名称。其他类似的内置变量包括 pid 和 tid
args是一个包含所有 tracepoint 参数的结构体。此结构体由 bpftrace 根据 tracepoint 信息自动生成。此结构体的成员可以通过以下命令找到
```bash
bpftrace -vl tracepoint:syscalls:sys_enter_openat
```
args.filename访问args结构并获取成员的值 filename。
str()将指针变成它指向的字符串。

## 按进程统计系统调用次数
```bash
bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }' 
```
@：表示一种称为 map 的特殊变量类型，它能够以不同的方式存储和汇总数据。您可以在 @ 后添加可选的变量名，例如“@num”，以提高可读性，或区分多个 map。
[]：可选的括号允许为地图设置一个键，就像关联数组一样。
count()：这是一个 map 函数——它的填充方式。count() 会计算其被调用的次数。由于它由 comm 保存，因此结果是按进程名称统计的系统调用频率。

当 bpftrace 结束时（例如，通过 Ctrl-C），会自动打印地图

## 统计on-cpu内核栈
```bash
bpftrace -e 'profile:hz:99 { @[kstack] = count(); }'
```
## 调度的跟踪
这会对导致上下文切换（非cpu）事件的堆栈跟踪进行计数。上面的输出已被截断，只显示最后两个。

sched: sched类别有针对不同内核CPU调度器事件的跟踪点：sched_switch、sched_wakeup、sched_migrate_task等。
sched_switch：这个探测在线程离开CPU时触发。这将是一个阻塞事件：例如，等待I/O、计时器、分页/交换或锁。
kstack：内核堆栈跟踪。
Sched_switch在线程上下文中触发，以便堆栈指向即将离开的线程。在使用其他探测类型时，请注意上下文，因为comm、pid、kstack等可能不指向探测的目标。
```bash
bpftrace -e 'tracepoint:sched:sched_switch { @[kstack] = count(); }'
```
## 阻塞 I/O跟踪
bpftrace -e 'tracepoint:block:block_rq_issue { @ = hist(args.bytes); }'

列出内核上所有可用的 Kprobe：
```
sudo cat /sys/kernel/debug/tracing/available_filter_functions
```

## reference:
* https://github.com/bpftrace/bpftrace/blob/master/man/adoc/bpftrace.adoc
* https://eunomia.dev/tutorials/bpftrace-tutorial/

