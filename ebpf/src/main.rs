use anyhow::{Context, Result};
use aya::{
    maps::{HashMap, PerfEventArray},
    Bpf,
};
use clap::Parser;
use pid_flamegraph::EbpfData;
use std::{
    collections::HashMap as StdHashMap, fs::File, io::Write, path::PathBuf, str, time::{Duration, Instant}
};

use svc::node::element::path::Data;
use svg::node::element::{Group, Path, Rectangle, Text};
use svg::Document;


#[derive(Parser, Debug)]
#[clap(about="generate process cpu", version, author)]
struct Opt {
    #[clap(short, long)]
    pid: u32,
    //  跟踪的时间
    #[clap(short, long, default_value = "10")]
    duration: u64,

    // output path
    #[clap(short, long, default_value_t = String::from("flamegraph.svg"))]
    output: String,
}

// 火焰图节点结构
#[derive(Debug, Clone)]
struct FlameNode {
    name: String,
    start: u64,
    end: u64,
    children: StdHashMap<String, FlameNode>,
}


impl FlameNode {
    fn new(name: String, start: u64) -> Self {
        FlameNode {
            name,
            start,
            end: start,
            children: StdHashMap::new(),
        }
    }

    fn add_child(&mut self, stack: &[String], start: u64, end: u64) {

        if stack.is_empty() {
            return;
        }

        let child_name = stack[0].clone();
        let remaining_stack = &stack[1..];
        
        let child = self.children.entry(child_name).or_insert_with(|| {
            FlameNode::new(child_name.clone(), start, end)
        });
        if !remaining_stack.is_empty() {
            child.add_child(remaining_stack, start, end);
        } else {
            child.start = child.start.min(start);
            child.end = child.end.max(end);
        }
    }
    fn duration(&self) -> u64 {
        self.end - self.start
    }
}

fn generate_flamegraph(root: &FlameNode, output_path: &str, total_time: u64) -> Result<()> {
    const WIDTH: u32 = 1200;
    const HEIGHT: u32 = 800;
    const CELL_HEIGHT: u32 = 20;
    const MAX_DEPTH: usize = (HEIGHT / CELL_HEIGHT) as usize;

    let mut document = Document::new()
        .set("width", WIDTH)
        .set("height", HEIGHT)
        .set("viewBox", (0, 0, WIDTH, HEIGHT));

    // 添加背景
    let background = Rectangle::new()
        .set("x", 0)
        .set("y", 0)
        .set("width", WIDTH)
        .set("height", HEIGHT)
        .set("fill", "#ffffff");
    document = document.add(background);

    // 递归绘制火焰图
    draw_flame_node(
        &mut document,
        root,
        0,
        0,
        WIDTH,
        CELL_HEIGHT,
        0,
        MAX_DEPTH,
        total_time,
    );

    // 保存SVG文件
    let mut file = File::create(output_path)?;
    file.write_all(document.to_string().as_bytes())?;
    println!("火焰图已保存至: {}", output_path);

    Ok(())
}

fn draw_flame_node(document: &mut Document,
    node: &FlameNode,
    x: u32,
    y: u32,
    width: u32,
    cell_height: u32,
    depth: usize,
    max_depth: usize,
    total_time: u64,) {
    if depth >= max_depth || node.children.is_empty() {
        return;
    }
    let total_duration = node.duration();
    let mut current_x = x;
 // 为每个子节点绘制矩形
    for (_, child) in &node.children {
        let child_duration = child.duration();
        let child_width = (child_duration as f64 / total_duration as f64 * width as f64) as u32;

        if child_width == 0 {
            continue;
        }

        // 生成颜色 (简单的哈希颜色)
        let hash = child.name.bytes().fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
        let r = ((hash >> 16) & 0xFF) as u8;
        let g = ((hash >> 8) & 0xFF) as u8;
        let b = (hash & 0xFF) as u8;
        let color = format!("#{:02x}{:02x}{:02x}", r, g, b);
        let bright_color = format!("#{:02x}{:02x}{:02x}", r/2 + 128, g/2 + 128, b/2 + 128);

        // 绘制矩形
        let rect = Rectangle::new()
            .set("x", current_x)
            .set("y", y)
            .set("width", child_width)
            .set("height", cell_height)
            .set("fill", color)
            .set("stroke", "#000000")
            .set("stroke-width", 1);
        document.add(rect);

        // 添加函数名文本
        if child_width > 50 {  // 只有足够宽才显示文本
            let text = Text::new()
                .set("x", current_x + 5)
                .set("y", y + cell_height - 5)
                .set("font-size", 12)
                .set("fill", "#000000")
                .add(svg::node::text::Text::new(child.name.clone()));
            document.add(text);
        }

        // 递归绘制子节点
        draw_flame_node(
            document,
            child,
            current_x,
            y + cell_height,
            child_width,
            cell_height,
            depth + 1,
            max_depth,
            total_time,
        );

        current_x += child_width;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();
    println!("跟踪进程 PID: {}, 持续时间: {}秒", opt.pid, opt.duration);

    // 加载eBPF程序
    let mut bpf = Bpf::load_file("target/bpfel-unknown-none/debug/pid-flamegraph")
        .context("加载eBPF程序失败")?;

    // 配置PerfEvent程序跟踪指定PID的CPU事件
    let program: &mut PerfEvent = bpf.program_mut("trace_function")
        .context("获取trace_function程序失败")?
        .try_into()?;
    
    // 仅跟踪指定PID的进程
    program.set_pid(opt.pid);
    // 跟踪CPU周期事件
    program.load(PerfTypeId::Software, 0, "cpu-clock")?;
    program.attach()?;

    // 获取PerfEventArray用于接收事件
    let mut perf_events = PerfEventArray::from_pin(bpf.map_mut("EVENTS")?)?;

    // 存储调用栈数据
    let mut stack_data: StdHashMap<u64, (Vec<String>, u64)> = StdHashMap::new();
    let mut root_node = FlameNode::new("root".to_string(), 0, 0);
    let start_time = Instant::now();

    // 创建事件处理器
    let mut buffers = vec![None; num_cpus::get()];
    let duration = Duration::from_secs(opt.duration);
    let end_time = start_time + duration;

    // 处理事件
    while Instant::now() < end_time {
        perf_events.poll(&mut buffers, Some(Duration::from_millis(100)))?;
        
        for buf in buffers.iter_mut().flatten() {
            while let Some(event) = buf.next::<EbpfData>()? {
                match event.event_type {
                    0 => {  // 函数进入
                        let stack_id = event.stack_id;
                        let func_name = String::from_utf8_lossy(&event.data[..event.data_len as usize]).to_string();
                        
                        // 如果是新的调用栈，创建一个新的
                        let entry = stack_data.entry(stack_id).or_insert_with(|| {
                            (vec![func_name.clone()], event.timestamp)
                        });
                        
                        // 将函数添加到调用栈
                        entry.0.push(func_name);
                    }
                    1 => {  // 函数退出
                        if let Some((stack, start_ts)) = stack_data.remove(&event.stack_id) {
                            // 将完整的调用栈添加到火焰图
                            root_node.add_child(&stack, start_ts, event.timestamp);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // 生成火焰图
    let total_time = root_node.duration();
    generate_flamegraph(&root_node, &opt.output, total_time)?;

    Ok(())
}
