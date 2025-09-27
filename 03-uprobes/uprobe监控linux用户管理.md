需求：监控/etc/passwd文件有没有被修改，用户可能通过vim来直接写入文件，需要监控/etc/passwd文件状态

用户态：
* load ebpf程序
* 读取事件并且格式化打印

ebpf程序：
* 你实现使用uprobe监听useradd, passwd等钩子函数
* 读取进程ip以及进程名字和文件名字
* 使用tracepoint监控sys_enter_write
* 过滤对/etc/passwd文件的写入操作
* 事件发送回去用户态

ebpf代码
```rust
// 定义事件结构
#[repr(u8)]
#[derive(Debug, Copy, Clone)]
pub enum EventType {
    UserAdd = 0,        // 添加用户
    PasswdChange = 1,   // 修改密码
    FileWrite = 2       // 写入文件
}

// 事件数据结构
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct UserEvent {
    pub event_type: EventType,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; 16],   // 进程名
    pub username: [u8; 32], // 用户名
    pub path: [u8; 128],  // 文件路径
}

// 定义RingBuf用于内核态到用户态的数据传输
#[map(name = "EVENTS")]
static mut EVENTS: RingBuf = RingBuf::new();


// 辅助函数：复制用户态字符串到缓冲区
fn copy_str(src: *const c_char, dest: &mut [u8]) {
    let mut i = 0;
    while i < dest.len() - 1 {
        unsafe {
            let c = bpf_probe_read_user_str(src.add(i), 1);
            if c == 0 {
                break;
            }
            dest[i] = c as u8;
        }
        i += 1;
    }
}

// 辅助函数：检查路径是否为/etc/passwd
fn is_passwd_path(path: &[u8]) -> bool {
    let target = b"/etc/passwd";
    path.starts_with(target) && (path.len() == target.len() || path[target.len()] == 0)
}


// uprobe：监控useradd命令
#[uprobe(name = "useradd_probe")]
pub fn useradd_probe(ctx: *mut pt_regs) {
    // x86_64架构：rsi寄存器是第二个参数(argv[1] - 用户名)
    let username_ptr = unsafe { (*ctx).si as *const c_char };
    if username_ptr.is_null() {
        return;
    }

    // 获取进程信息
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let uid_gid = unsafe { bpf_get_current_uid_gid() };
    let uid = uid_gid as u32;
    let gid = (uid_gid >> 32) as u32;
    
    let mut comm = [0u8; 16];
    unsafe { bpf_get_current_comm(&mut comm, comm.len() as _) };

    // 读取用户名
    let mut username = [0u8; 32];
    copy_str(username_ptr, &mut username);

    // 构造事件
    let event = UserEvent {
        event_type: EventType::UserAdd,
        pid,
        tid,
        uid,
        gid,
        comm,
        username,
        path: [0u8; 128],
    };

    // 发送事件
    unsafe {
        if let Some(mut ring_event) = EVENTS.reserve::<UserEvent>() {
            *ring_event = event;
            ring_event.submit();
        }
    }
}

// uprobe：监控passwd命令
#[uprobe(name = "passwd_probe")]
pub fn passwd_probe(ctx: *mut pt_regs) {
    // x86_64架构：rsi寄存器是第二个参数(argv[1] - 用户名，可能为NULL)
    let username_ptr = unsafe { (*ctx).si as *const c_char };

    // 获取进程信息
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let uid_gid = unsafe { bpf_get_current_uid_gid() };
    let uid = uid_gid as u32;
    let gid = (uid_gid >> 32) as u32;
    
    let mut comm = [0u8; 16];
    unsafe { bpf_get_current_comm(&mut comm, comm.len() as _) };

    // 读取用户名
    let mut username = [0u8; 32];
    if username_ptr.is_null() {
        // 如果没有指定用户名，使用当前用户
        username[..7].copy_from_slice(b"current");
    } else {
        copy_str(username_ptr, &mut username);
    }

    // 构造事件
    let event = UserEvent {
        event_type: EventType::PasswdChange,
        pid,
        tid,
        uid,
        gid,
        comm,
        username,
        path: [0u8; 128],
    };

    // 发送事件
    unsafe {
        if let Some(mut ring_event) = EVENTS.reserve::<UserEvent>() {
            *ring_event = event;
            ring_event.submit();
        }
    }
}

// tracepoint：监控write系统调用
#[tracepoint(name = "write_probe")]
pub fn write_probe(ctx: *mut pt_regs) {
    // sys_enter_write参数：rdi=fd, rsi=buf, rdx=count
    let fd = unsafe { (*ctx).di as c_int };
    
    // 通过fd获取文件路径
    let mut path = [0u8; 128];
    unsafe {
        bpf_d_path(
            fd as *const _,
            path.as_mut_ptr(),
            path.len() as u32
        );
    }

    // 检查是否是/etc/passwd
    if !is_passwd_path(&path) {
        return;
    }

    // 获取进程信息
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    let uid_gid = unsafe { bpf_get_current_uid_gid() };
    let uid = uid_gid as u32;
    let gid = (uid_gid >> 32) as u32;
    
    let mut comm = [0u8; 16];
    unsafe { bpf_get_current_comm(&mut comm, comm.len() as _) };

    // 构造事件
    let event = UserEvent {
        event_type: EventType::FileWrite,
        pid,
        tid,
        uid,
        gid,
        comm,
        username: [0u8; 32],
        path,
    };

    // 发送事件
    unsafe {
        if let Some(mut ring_event) = EVENTS.reserve::<UserEvent>() {
            *ring_event = event;
            ring_event.submit();
        }
    }
}

```


用户态代码：
```rust

#[derive(Debug, Parser)]
struct Opt {
    /// 要监控的useradd路径
    #[clap(short, long, default_value = "/usr/sbin/useradd")]
    useradd_path: String,

    /// 要监控的passwd路径
    #[clap(short, long, default_value = "/usr/bin/passwd")]
    passwd_path: String,
}

// 与eBPF程序中的事件类型同步
#[repr(u8)]
#[derive(Debug, Copy, Clone)]
enum EventType {
    UserAdd = 0,
    PasswdChange = 1,
    FileWrite = 2,
}

// 与eBPF程序中的事件结构同步
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct UserEvent {
    event_type: EventType,
    pid: u32,
    tid: u32,
    uid: u32,
    gid: u32,
    comm: [u8; 16],
    username: [u8; 32],
    path: [u8; 128],
}

// 辅助函数：将字节数组转换为字符串
fn bytes_to_str(bytes: &[u8]) -> &str {
    CStr::from_bytes_until_nul(bytes)
        .ok()
        .and_then(|cstr| cstr.to_str().ok())
        .unwrap_or("invalid string")
}


#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    // 加载eBPF程序
    let mut bpf = Bpf::load_file("target/bpfel-unknown-none/debug/user-monitor-ebpf")
        .context("无法加载eBPF程序")?;

    // 初始化eBPF日志
    aya_log::EbpfLogger::init(&mut bpf)?;

    // 配置useradd uprobe
    if Path::exists(Path::new(&opt.useradd_path)) {
        let mut useradd_probe = UProbe::try_from(bpf.program_mut("useradd_probe")?)?;
        useradd_probe.set_path(&opt.useradd_path)?;
        useradd_probe.set_symbol("main")?;
        useradd_probe.attach(None)?;
        info!("已挂钩 useradd: {}", opt.useradd_path);
    } else {
        warn!("未找到useradd: {}", opt.useradd_path);
    }

    // 配置passwd uprobe
    if Path::exists(Path::new(&opt.passwd_path)) {
        let mut passwd_probe = UProbe::try_from(bpf.program_mut("passwd_probe")?)?;
        passwd_probe.set_path(&opt.passwd_path)?;
        passwd_probe.set_symbol("main")?;
        passwd_probe.attach(None)?;
        info!("已挂钩 passwd: {}", opt.passwd_path);
    } else {
        warn!("未找到passwd: {}", opt.passwd_path);
    }

    // 配置write tracepoint
    let mut write_tracepoint = TracePoint::try_from(bpf.program_mut("write_probe")?)?;
    write_tracepoint.attach("syscalls", "sys_enter_write")?;
    info!("已挂钩 sys_enter_write tracepoint");

    // 获取RingBuf映射
    let mut ringbuf = RingBuf::try_from(bpf.map_mut("EVENTS")?)
        .context("无法获取EVENTS映射")?;

    // 处理事件
    info!("开始监控用户管理事件...");
    loop {
        let event = ringbuf.next_event::<UserEvent>().await
            .context("读取事件失败")?;

        let comm = bytes_to_str(&event.comm);
        let username = bytes_to_str(&event.username);
        let path = bytes_to_str(&event.path);
        let ip = get_process_ip(event.pid);

        match event.event_type {
            EventType::UserAdd => {
                info!(
                    "[用户添加] PID={} TID={} UID={} GID={} 进程={} IP={} 用户名={}",
                    event.pid, event.tid, event.uid, event.gid, comm, ip, username
                );
            }
            EventType::PasswdChange => {
                info!(
                    "[密码修改] PID={} TID={} UID={} GID={} 进程={} IP={} 用户名={}",
                    event.pid, event.tid, event.uid, event.gid, comm, ip, username
                );
            }
            EventType::FileWrite => {
                info!(
                    "[文件写入] PID={} TID={} UID={} GID={} 进程={} IP={} 路径={}",
                    event.pid, event.tid, event.uid, event.gid, comm, ip, path
                );
            }
        }
    }
}
```