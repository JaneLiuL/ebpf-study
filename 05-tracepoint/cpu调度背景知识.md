执行以下命令可以查看tracepoint跟调度相关，这里我们主要讲一下cpu调度的背景知识
`bpftrace -l 'tracepoint:sched:*' `

我们来查看'tracepoint:sched:sched_switch' ，这是属于cpu进程相关调度相关的一个函数，通过该函数我们可以看到进程或者线程执行cpu调度切换，通常发生在上一个进程的cpu被下一个进程获取cpu
```bash
# tracepoint:sched:sched_switch我们常用来监控进程切换频率，分析调度延迟等
bpftrace -l 'tracepoint:sched:sched_switch' -v
tracepoint:sched:sched_switch
    char prev_comm[16]
    pid_t prev_pid
    int prev_prio
    long prev_state
    char next_comm[16]
    pid_t next_pid
    int next_prio

```
从上面可以看到prev_pid 就是即将让出cpu的进程，next_prio是即将获得cpu的进程
我们通过下面来计算实际cpu运行的时间
当进程 A 被调度进来（作为 next）时，记录当前时间点 t1
当进程 A 被调度出去（作为 prev）时，记录当前时间点 t2
进程 A 的本次 CPU 占用时间 = t2 - t1


下面是使用rust aya的一个例子
```rust
#[map(name = "PROCESS_STATS")]
static mut PROCESS_STATS: HashMap<u32, ProcessStats> = HashMap::with_max_entries(1024, 0);
#[derive(Debug, Default)]
struct ProcessStats {
    runtime_ns: u64,
    sleep_count: u32,
    switch_count: u32,
}


#[tracepoint(name = "sched_switch")]
pub fn sched_switch(ctx: TracePointContext) -> u32 {
    match try_sched_switch(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_sched_switch(ctx: TracePointContext) -> Result<(), ()> {
    // 解析sched_switch参数，获取前一个进程和新进程信息
    let args = unsafe { mem::transmute::<_, &sched__sched_switch_args>(ctx.args()) };
    let prev_pid = args.prev_pid as u32;
    let next_pid = args.next_pid as u32;
    
    unsafe {
        // 更新切换计数
        if prev_pid != 0 {
            let stats = PROCESS_STATS.entry(prev_pid).or_insert(ProcessStats::default());
            stats.switch_count += 1;
        }
        
        info!(
            &ctx,
            "Process switch: {} -> {}. Switch count for {}: {}",
            prev_pid, next_pid, prev_pid, 
            PROCESS_STATS.get(&prev_pid).map_or(0, |s| s.switch_count)
        );
    }
    
    Ok(())
}
```


`tracepoint:sched:sched_stat_runtime`这个函数主要是进程的时间片用完时触发，用于记录进程实际运行的实际，统计进程的运行时长
```bash
bpftrace -l 'tracepoint:sched:sched_stat_runtime' -v
tracepoint:sched:sched_stat_runtime
    char comm[16]
    pid_t pid
    u64 runtime
```