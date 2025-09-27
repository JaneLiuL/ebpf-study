
uprobe是用于监控用户空间的比如一些函数
这里我们讲一下大概uprobe ebpf的流程，我们现在实现一个ebpf uprobe监控openssl函数来实现https嗅探器

用户实现：
* 需要找到vm的openssl中处理tls的函数，使用`ldd `which curl` | grep -E ssl`命令可以找到openssl函数位置
* load ebpf程序
* 配置uprobe来挂钩openssl的函数
* 从RingBuf 接受ebpf发送的事件
* 处理事件

内核ebpf实现
* 挂钩openssl函数
* 读取触发的进程名字，读取进程数据包，读取用户态需要使用bpf_probe_read_user， 然后把明文数据传输回去用户空间

细节实现
用户态：
```rust

// 事件结构：包含进程信息、连接信息和明文数据
#[repr(C)]
#[derive(Debug)]
pub struct SslEvent {
    pub pid: u32,               // 进程 ID
    pub tid: u32,               // 线程 ID
    pub fd: c_int,              // socket 文件描述符
    pub is_write: bool,         // true=SSL_write，false=SSL_read
    pub data_len: usize,        // 明文长度（实际有效数据）
    pub data: [u8; 1024],       // 明文数据（截断为 1024 字节，避免过大）
}
async fn main() -> Result<()> {
    ...加载ebpf程序
    // 配置uprobe挂钩openssl库
    let libssl_path = "/usr/lib/x86_64-linux-gnu/libssl.so.3";  // 替换为系统中的 libssl 路径
    if !Path::exists(Path::new(libssl_path)) {
        return Err(anyhow::anyhow!("未找到 libssl.so，请检查路径是否正确"));
    }

    //  2.1 挂钩 SSL_read 函数
    let mut ssl_read_uprobe = UProbe::try_from(bpf.program_mut("ssl_read_uprobe")?)?;
    ssl_read_uprobe.set_path(libssl_path)?;  // 指定目标库路径
    ssl_read_uprobe.set_symbol("SSL_read")?; // 指定要挂钩的函数名
    ssl_read_uprobe.attach(None)?;           // None 表示监控所有调用该库的进程

    // 3. 从 RingBuf 接收 eBPF 发送的事件
    let mut ringbuf = RingBuf::try_from(bpf.map_mut("EVENTS")?)
        .context("获取 RingBuf 映射失败")?;

// }   处理事件，比如直接打印
```



内核ebpf实现细节
```rust

// 事件结构：包含进程信息、连接信息和明文数据
#[repr(C)]
#[derive(Debug)]
pub struct SslEvent {
    pub pid: u32,               // 进程 ID
    pub tid: u32,               // 线程 ID
    pub fd: c_int,              // socket 文件描述符
    pub is_write: bool,         // true=SSL_write，false=SSL_read
    pub data_len: usize,        // 明文长度（实际有效数据）
    pub data: [u8; 1024],       // 明文数据（截断为 1024 字节，避免过大）
}


// uprobe 挂钩 SSL_read 函数（用户态函数）
// 注意：uprobe 会在函数**入口**触发
#[uprobe(name = "ssl_read_uprobe")]
pub fn ssl_read_uprobe(ctx: *mut pt_regs) {
    // x86_64 架构用户态函数参数通过寄存器传递：
    // rdi: 第一个参数（SSL* ssl）
    // rsi: 第二个参数（void* buf，明文缓冲区）
    // rdx: 第三个参数（int len，数据长度）
    let ssl = unsafe { (*ctx).di as *mut SSL };
    let buf = unsafe { (*ctx).si as *const c_char };
    let len = unsafe { (*ctx).dx as size_t };

    // 处理事件，标记为读取操作
    handle_ssl_event(ssl, buf, len, false);
}


// 通用事件处理逻辑
fn handle_ssl_event(ssl: *mut SSL, buf: *const c_char, len: size_t, is_write: bool) {
    // 获取当前进程 PID 和 TID（低 32 位是 TID，高 32 位是 PID）
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    // 调用 OpenSSL 的 SSL_get_fd 获取 socket 文件描述符
    let fd = unsafe { SSL_get_fd(ssl) };
    if fd < 0 {
        info!("获取 socket fd 失败，fd={}", fd);
        return;
    }


    // 读取用户态内存中的明文数据（限制最大长度，防止溢出）
    let max_data_len = 1024;
    let data_len = len.min(max_data_len);  // 实际有效长度
    let mut data = [0u8; max_data_len];    // 存储明文的缓冲区


    // 安全读取用户态内存（内核态不能直接访问用户态内存，必须用 bpf_probe_read_user）
    unsafe {
        bpf_probe_read_user(
            data.as_mut_ptr() as *mut _,  // 目标缓冲区（内核态）
            data_len,                     // 读取长度
            buf as *const _                // 源地址（用户态）
        );
    }
// 构造事件
    let event = SslEvent {
        pid,
        tid,
        fd,
        is_write,
        data_len,
        data,
    };

    // 发送事件到用户态（通过 RingBuf）
    unsafe {
        // 申请 RingBuf 空间，存储事件
        if let Some(mut ring_event) = EVENTS.reserve::<SslEvent>() {
            *ring_event = event;  // 复制事件数据
            ring_event.submit();  // 提交事件（用户态可见）
        }
    }

```