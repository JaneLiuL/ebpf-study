#![allow(dead_code)]

use aya_bpf::bindings::u32;
use aya_bpf::macros::map;
use aya_bpf::maps::{HashMap, PerfEventArray};
use aya_bpf::programs::ProbeContext;
use aya_bpf::BpfContext;
use core::mem;
use kernel::prelude::*;


// 定义eBPF和用户态共享的数据结构
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EbpfData {
    pub pid: u32,
    pub stack_id: u64,
    pub timestamp: u64,
    pub event_type: u8, // 0: 进入, 1: 退出
    pub data_len: u8,
    pub data: [u8; 64], // 存储函数名
}

impl Default for EbpfData {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

// 存储进程的调用栈
#[map(name = "STACKS")]
pub static mut STACKS: HashMap<u64, [u64; 32]> = HashMap::with_max_entries(10240, 0);

// 用于向用户态发送事件的PerfEventArray
#[map(name = "EVENTS")]
pub static mut EVENTS: PerfEventArray<EbpfData> = PerfEventArray::new(0);

// 栈ID计数器
#[map(name = "STACK_ID_COUNTER")]
pub static mut STACK_ID_COUNTER: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

// 获取下一个栈ID
pub unsafe fn get_next_stack_id() -> u64 {
    let id = STACK_ID_COUNTER.entry(0).or_insert(0);
    *id += 1;
    *id
}

// 获取函数名
pub unsafe fn get_func_name(ctx: &ProbeContext) -> &[u8] {
    let ip = ctx.ip();
    let sym = kernel::kallsyms_lookup(ip as _);
    sym.name()
}