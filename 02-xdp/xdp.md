统计传入的udp包，使用 `PerCpuArray` eBPF映射
一旦计算超过阈值就重定向该数据包的目的地址以及目的端口

针对udp的洪水攻击，攻击者会发送大量的udp包，服务器收到数据包的时候会首先查看北极是否有程序在udp到达的端口上等待数据包，如果端口上没有任何程序，服务器就返回一个icmp数据包表示目的地无法到达，这个来回通信会消耗大量服务器资源

大概思路：
* 把每一个进入xdp的数据包获取
* 揭开数据包包头，如果不是ipv4协议则直接pass放过该数据包
* 查看数据包协议，如果是tcp则直接pass放过该数据包
* 如果端口是53端口，直接pass放过该数据包
* 计算数据包如果超过阈值，则修改目的地址和目的端口

为什么使用xdp而不是tc是因为xdp是每个数据包传入网络设备的时候被触发的hooker，
tc是数据包进入和传出的时候都会触发

为什么使用`PerCpuArray`而不是`non-PerCUPArray`呢？
这是处理内存方式不同，
perCpu是每个cpu都有分配单独的一块内存区域，可以避免多个cpu同时访问映射发生冲突
non-PerCPu是所有cpu共享一块内存区域，共同访问的时候容易发生冲突
cpu直接不存在争用，使用`PerCpuArray`可以避免锁操作
```
   CPU 0   |   CPU 1   |   CPU 2   |   CPU 3
-----------|-----------|-----------|-----------
[         ]|[         ]|[         ]|[         ]
[ Data 0  ]|[ Data 1  ]|[ Data 2  ]|[ Data 3  ]
[         ]|[         ]|[         ]|[         ]
-----------|-----------|-----------|-----------

```

如何测试：
首先模拟攻击者，
发送1000个udp数据包
nc -u -w 1000 $TARGET_IP $TARGET_PORT

验证是否数据包被转发，使用`tcpdump`
# 抓目标端口 65500 的 UDP 包
tcpdump -i any udp port 65500 and host 192.168.0.10


## 把每一个进入xdp的数据包获取
```rust

// 这个函数返回的是*mut T 是一个可变的指针，是为了我们需要最后修改数据包
#[inline(always)]
fn get_mut_ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ExecutionError> {
    let ptr: *const T = get_ptr_at(ctx, offset)?;
    Ok(ptr as *mut T)   

}

// 这个函数返回的是*const T，是不加修改的读取数据的常量指针
#[inline(always)]
fn get_ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ExecutionError> {
    // ctx.data是拿到数据包的开始
    let start = ctx.data();
    // ctx.data是拿到数据包的末尾
    let end = ctx.data_end();
    let len = mem::size_of::<T>();


    let new_ptr = start
            .checked_add(offset)
            .ok_or(ExecutionError::PointerOverflow)?;
    let new_end = new_ptr
            .checked_add(len)
            .ok_or(ExecutionError::PointerOverflow)?;
            // 检查数据包是否溢出
    if new_end > end {
        return Err(ExecutionError::PointerOutOfBounds);
    }
    Ok((start + offset) as *const T)
    
}

```

## 揭开数据包包头，如果不是ipv4协议则直接pass放过该数据包
```rust
let eth_hdr: *mut EthHdr = get_mut_ptr_at(&ctx, 0)?;
    match unsafe {(*eth_hdr).ether_type} {
        EtherType::IPv4 => {
            // IPv4 packet
            info!(&ctx, "IPv4 packet received");
        },
        // 0x0800 => {
        //     // IPv4 packet
        //     info!(&ctx, "IPv4 packet received");
        // },
        // 0x86DD => {
        //     // IPv6 packet
        //     info!(&ctx, "IPv6 packet received");
        // },
        _ => {
            // Unsupported packet type
            info!(&ctx, "Unsupported packet type received");
            return Ok(xdp_action::XDP_PASS);
        }
        
    }
```

## 查看数据包协议，如果是不是udp则直接pass放过该数据包
```rust
let ip_hdr: *mut EthHdr = get_mut_ptr_at(&ctx, EthHdr::LEN)?;
    match unsafe { {*ip_hdr}.proto} {
        IpProto::Udp => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }
```

## 如果数据包是53的直接pass
```rust
let udp_hdr: *const UdpHdr = get_ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let port = u16::from_be(unsafe { (*udp_hdr).dest });

    if port == 53 {
        return Ok(xdp_action::XDP_PASS);
    }
```

## 获取所有cpu上的数据包总数
```rust
#[inline(always)]
fn get_total_cpu_counter(cpu_cores: u32) -> u32 {
    let mut sum: u32 = 0;
    for cpu in 0..cpu_cores {
        let c = unsafe {
    
            bpf_map_lookup_percpu_elem(
                &mut COUNTER as *mut _ as *mut c_void,
                &0 as *const _ as *const c_void,
                cpu,
            )
        };
        
        if !c.is_null() {
            unsafe {
                let counter = &mut *(c as *mut u32);
                sum += *counter;
            }
        }
    }
    sum
}
```

## 计算数据包如果超过阈值，则修改目的地址和目的端口
```rust
    let total = get_total_cpu_counter();
    if total >= THRESHOLD {
        unsafe {
            // Change the destination MAC addresses and Ip to the honeypot
            (*eth_hdr).dst_addr = [0xF0, 0x2F, 0x4B, 0x14, 0x2D, 0x78];
            (*ip_hdr).dst_addr = u32::from_be_bytes([192, 168, 2, 37]).to_be();
            // Set Mac address of the packet to the current interface MAC address
            (*eth_hdr).src_addr = [0xbc, 0x09, 0x1b, 0x98, 0x40, 0xae];

			let cpu = bpf_get_smp_processor_id();
            info!(
                &ctx,
                "CPU: {} is redirecting UDP packet to honeypot ip: {:i}, mac: {:mac}",
                cpu,
                u32::from_be((*ip_hdr).dst_addr),
                (*eth_hdr).dst_addr
            );
        }
        // XDP_TX 用来快速将网络数据包从到达的网络接口发送回去
        return Ok(xdp_action::XDP_TX);
    }
```
