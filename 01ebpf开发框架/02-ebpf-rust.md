
如何实现从ebpf程序读取用户空间传进去的数据？
举例要传输用户态的某个pid 1234到 ebpf程序中

主要思路是定义一个比如HashMap 类型的ebpf映射存储要监控的pid
用户态讲pid写入 hashmap
ebpf检查当前pid是否在映射中

用户态代码
```rust
use clap::Parser;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: u32,
}


fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // 加载eBPF程序
    let mut bpf = Bpf::load(include_bytes_aligned!(../../target/bpfel-unknown-none/release/ebpf))?;
    BpfLogger::init(&mut bpf)?;

    // 获取PID映射
    let mut monitored_pids = bpf.map_mut("MONITORED_PIDS")?;
    
    // 将用户指定的PID写入映射
    monitored_pids.insert(opt.pid, &1u8, 0)?;
    info!("Added PID {} to monitored list", opt.pid);

    // 附加kprobe到sys_execve
    let program: &mut aya::programs::KProbe = bpf.program_mut("sys_execve")?.try_into()?;
    program.attach("__x64_sys_execve", None)?;

    info!("Waiting for events...");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

```
ebpf代码
```rust

// 定义存储要监控的PID的映射
#[map(name = "MONITORED_PIDS")]
static mut MONITORED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[kprobe(name = "sys_execve")]
pub fn sys_execve(ctx: KProbeContext) -> u32 {
    let pid = ctx.pid();
    
    // 检查当前PID是否在监控列表中
    unsafe {
        if MONITORED_PIDS.get(&pid).is_some() {
            info!(ctx, "Monitored process executed execve: PID {}", pid);
        }
    }
    
    0
}
```

如何实现从内核ebpf程序中传输数据回到用户空间呢
举例，内核ebpf需要做
* 定义ebpf侧PerfEventArray<NetworkEvent>映射作为传输通道
* 构造 NetworkEvent 结构体存储要传输的数据
* 通过 EVENTS.output(...) 方法将事件发送到用户空间
那么在用户空间侧：
* 创建PerfBuffer监听内核事件
* 通过perf_buffer.poll(...) 循环接收事件
解析事件数据并处理（如打印日志）

ebpf侧代码：
```rust

// 定义要传输到用户空间的事件结构
#[derive(Debug)]
#[repr(C)]
pub struct NetworkEvent {
    pub src_ip: u32,    // 源 IP 地址（网络字节序）
    pub dst_ip: u32,    // 目的 IP 地址（网络字节序）
    pub src_port: u16,  // 源端口（网络字节序）
    pub dst_port: u16,  // 目的端口（网络字节序）
    pub pid: u32,       // 关联进程 PID
}

// 定义 Perf 环形缓冲区，用于向用户空间发送事件
#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<NetworkEvent> = PerfEventArray::new();


#[xdp(name = "network_monitor")]
pub fn network_monitor(ctx: XdpContext) -> u32 {
    // 解析以太网头部
    let eth = unsafe { &*ctx.data().offset(0).unwrap() };
    if eth.h_proto != u16::from_be_bytes([0x08, 0x00]) {
        // 不是 IPv4 包，直接通过
        return xdp_action::XDP_PASS;
    }

    // 解析 IPv4 头部
    let ip_hdr = unsafe { &*ctx.data().offset(mem::size_of::<EthHdr>() as i32).unwrap() };
    let ip_data = ctx.data().offset((mem::size_of::<EthHdr>() + mem::size_of::<Ipv4Hdr>()) as i32).unwrap();
    
    // 简单提取端口（假设是 TCP/UDP，仅作示例）
    let (src_port, dst_port) = unsafe {
        let ports = &*ip_data.offset(0).unwrap() as *const u8 as *const [u8; 4];
        (
            u16::from_be_bytes([(*ports)[0], (*ports)[1]]),
            u16::from_be_bytes([(*ports)[2], (*ports)[3]]),
        )
    };

    // 获取当前进程 PID
    let pid = ctx.pid_tgid() >> 32;

    // 构造事件
    let event = NetworkEvent {
        src_ip: ip_hdr.saddr,
        dst_ip: ip_hdr.daddr,
        src_port,
        dst_port,
        pid,
    };

    // 发送事件到用户空间（通过 Perf 环形缓冲区）
    unsafe {
        EVENTS.output(&ctx, &event, 0);
    }

    info!(ctx, "Captured packet: src={:i}, dst={:i}, pid={}", 
          ip_hdr.saddr, ip_hdr.daddr, pid);

    xdp_action::XDP_PASS
}
```

用户态代码：
```rust

// 必须与 eBPF 程序中的事件结构保持一致
#[derive(Debug)]
#[repr(C)]
pub struct NetworkEvent {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub pid: u32,
}


fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    // 初始化日志
    env_logger::init();

    // 加载 eBPF 程序
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/network_monitor"
    ))?;
    BpfLogger::init(&mut bpf)?;

    // 获取 Perf 环形缓冲区映射
    let events = bpf.map_mut("EVENTS")?;
    // 创建 Perf 缓冲区处理器
    let mut perf_buffer = aya::maps::PerfBuffer::builder(events)
        .poll_timeout_ms(100)
        .build()?;

    // 附加 XDP 程序到网络接口
    let program: &mut aya::programs::Xdp = bpf.program_mut("network_monitor")?.try_into()?;
    program.attach(&opt.iface, None)?;

    info!("Monitoring network events on interface {}", opt.iface);

    // 循环处理从内核发送的事件
    loop {
        perf_buffer.poll(|_cpu, data: &[u8]| {
            // 解析事件数据
            let event = unsafe { &*(data.as_ptr() as *const NetworkEvent) };
            
            // 转换网络字节序为可读格式
            let src_ip = Ipv4Addr::from(event.src_ip);
            let dst_ip = Ipv4Addr::from(event.dst_ip);
            let src_port = u16::from_be(event.src_port);
            let dst_port = u16::from_be(event.dst_port);

            info!(
                "Received event: PID={}, Src={}:{}, Dst={}:{}",
                event.pid, src_ip, src_port, dst_ip, dst_port
            );
        })?;
    }
```