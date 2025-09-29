以go程序为例子，如果需要编写go程序的火焰图需要了解以下知识
学习 Go 程序的编译原理：了解gopclntab、符号表、调试信息（-buildmode=pie等编译选项对符号的影响）。

使用go test -bench . -cpuprofile cpu.pprof生成 CPU profile，并用go tool pprof -http=:8080 cpu.pprof查看火焰图。

手动编写一个简单的 Go 程序（含嵌套函数调用），生成并分析其火焰图。

理解 Linux 进程模型：PID、TGID、虚拟内存布局（结合/proc/<pid>/maps）。


# go编译流程
go编译大概流程是静态检查，语法检查，机器码生成，将多个目标文件合并为可执行文件同时处理符号表等
因此在最终生成可执行文件中会包含：
* 机器码
* 符号表
* gopclntab
* 调试信息


# 什么是gopclntab
go 程序在编译的时候会嵌入一段数据，用来记录内存中指令地址和源码文件路径函数名的对应关系


# 符号表
符号表是程序中所有函数，变量，类型等标识符与其内存地址的映射表，用于链接 调试和动态加载


# 符号表和函数变量和 gopclntab 的关系
函数和变量就是程序的核心实体
符号表就是记录这些实体的身份和地址
gopclntab专注于函数与源码位置的映射
栈 ID 标识调用栈中的具体位置，符号表和 gopclntab 则负责将这些底层地址 “翻译” 为人类可读的函数 / 变量名和源码位置

# Linux 进程模型
 Linux 进程模型：PID、TGID、虚拟内存布局（结合/proc/<pid>/maps）
进程和线程的关系
在linux内核里面，内核统一用task_struct人物结构体来描述可以调度的实体，每个task_struct都有一个唯一的PID也就是进程ID
在用户视角，需要区分独立进程和进程内的线程，需要 `TGID`也就是线程组ID来标志：
* 独立进程： 一个进程只有一个线程，也就是`PID = TGID`
* 多线程进程： 一个进程会有多个线程，所有线程的 TGID相同，比如下面代码，是一个有多个线程的的程序
```bash
root@lima-ubuntu-x86:~/demo# ps -ef | grep main
root      569726  330942  8 09:53 pts/6    00:00:00 go run ./main.go
root      569799  196531  0 09:53 pts/3    00:00:00 grep --color=auto main
root@lima-ubuntu-x86:~/demo# ps -L -p 569726
    PID     LWP TTY          TIME CMD
 569726  569726 pts/6    00:00:00 go
 569726  569727 pts/6    00:00:00 go
 569726  569728 pts/6    00:00:00 go
 569726  569729 pts/6    00:00:00 go
 569726  569730 pts/6    00:00:00 go
 569726  569731 pts/6    00:00:00 go
 569726  569732 pts/6    00:00:00 go
 569726  569733 pts/6    00:00:00 go
 569726  569745 pts/6    00:00:00 go
 569726  569757 pts/6    00:00:00 go
```

Linux为每个进程都分配独立的虚拟内存空间，每个进程的虚拟地址空间都独立
我们可以使用`/proc/pid/maps`来查看进程的虚拟内存布局
还是上面这个进程，我们查看输出虚拟地址从小到大排序，每一行代表一个内存区域
格式为
<虚拟地址范围>  <权限>  <偏移>  <设备号>  <inode>  <路径/说明>

```bash
cat /proc/569726/maps
00010000-005a3000 r-xp 00000000 00:30 4786                               /Users/jane/workspace/lima-workspace/go/bin/go
4000000000-4000400000 rw-p 00000000 00:00 0 
4000400000-4000c00000 rw-p 00000000 00:00 0                              [anon: Go: heap]
4000c00000-4004000000 ---p 00000000 00:00 0 
fc8f3b2fb000-fc8f3b2fe000 r--s 00000000 fd:01 1339693                    /root/.cache/go-build/fb/fbc82dfd02e345c78b61658b1bf7d8fdfc29e8bd10ac99a4649b986ea32a23ee-d
fc8f3b2fe000-fc8f3b33e000 rw-p 00000000 00:00 0                          [anon: Go: immortal metadata]
fc8f3b33e000-fc8f3b34e000 rw-p 00000000 00:00 0                          [anon: Go: gc bits]
4d8d2e287a48d63ddaf3ad3e79c24fb85485d792efbfbeb7f2e3a96511b29c3b-d
fc8f3b580000-fc8f3b600000 rw-p 00000000 00:00 0                          [anon: Go: immortal metadata]
fc8f3b600000-fc8f3d600000 rw-p 00000000 00:00 0 
fc8f3d600000-fc8f3d680000 ---p 00000000 00:00 0  
bbb64e2198507fb508b2be69aa7820db7b9080333c0cfa7ae199f5834cfdc29a-d
fc8f81e2f000-fc8f81e35000 r--s 00000000 fd:01 1359352                    /root/.cache/go-build/9d/9d69c9a2ae5fe14796864d5c3b71ceb7fbdc5ec1dc28e72e98b314cedbefe0d9-d
fc8f81e35000-fc8f81e39000 rw-s 00000000 fd:01 1339256                    /root/.config/go/telemetry/local/go@go1.25.0-go1.25.0-linux-arm64-2025-09-29.v1.count
fc8f81e39000-fc8f81eb9000 rw-p 00000000 00:00 0                          [anon: Go: immortal metadata]
fc8f81eb9000-fc8f81ed9000 rw-p 00000000 00:00 0 
fc8f820eb000-fc8f8214b000 rw-p 00000000 00:00 0 
fc8f8214b000-fc8f8214d000 r--p 00000000 00:00 0                          [vvar]
fc8f8214d000-fc8f8214f000 r-xp 00000000 00:00 0                          [vdso]
ffffe30cb000-ffffe30ec000 rw-p 00000000 00:00 0                          [stack]
```
而/proc/<pid>/exe 是告诉内核，进程的来源文件，是告诉进程最初是从哪个可执行文件启动的以及这些内容在虚拟地址空间中的位置
/proc/<pid>/maps是告诉内核，进程的虚拟内存里面加载了哪些内容代码数据 等