
需求，使用ebpf获取go 进程性能分析，并且生成火焰图

ebpf侧：
* 获取监控的进程id
* 使用perf_event 过滤该进程的栈id 以及内核栈id 写入map，注意perf_event是 进程使用cpu的时候
* 使用tracepoint 的try_sched_switch，hook住 cpu切换的时候，查看prev_pid是否是我们监控的进程id， 如果是并且该进程运行时间超过1毫秒的情况下就把 进程的栈id 以及内核栈id 写入map， 注意这个时候是进程被切换 cpu的时候，所以是SAMPLE_TYPE_OFF_CPU


用户空间侧：
* 从映射中读取栈ID
* 将栈ID的对应地址解析成函数名（符号解析）
* 输出数据比如生成火焰图


