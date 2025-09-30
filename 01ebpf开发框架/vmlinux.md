我们经常在一些ebpf项目里面都可以看到`#include vmlinux.h`, 这个文档时说这个是什么来的，为什么我们需要使用它

举例，我们需要在bpf程序里面检查task_struct的值，那么我们就需要知道这个struct 的具体类型定义，但是不同内核通常来说会有一些变化，也就是说，如果要让我们的bpf程序一次编译在不同内核运行是可能会有问题的，毕竟类型会变化

我们在使用当前内核生成的`vmlinux.h` ，如果需要一次编译到处运行，我们就需要使用 `libbpf`库比如 `bpf_core_read`，他会试图分析访问的字段在当前的内核发生了什么移动，来自动找到对应的字段


```c
// Kernel 5.4
struct task_struct {
    int pid;
    char comm[16];
    // ... 其他字段
};

// Kernel 5.10 - 字段移动了！
struct task_struct {
    char comm[16];
    int pid;        // 不同的偏移量！
    // ... 其他字段
};

```
CO-RE 技术基于 BTF（BPF 类型格式）实现，使 eBPF 程序在运行时感知内核版本，而无需为每个内核重新编译。
```c
#include "vmlinux.h"  // 生成的BTF类型

struct task_struct *task = (struct task_struct *)bpf_get_current_task();

// CO-RE在加载时自动调整字段偏移！
int pid = BPF_CORE_READ(task, pid);
```

# rust项目里面使用vmlinux
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h


cargo install bindgen-cli
cargo install --git https://github.com/aya-rs/aya -- aya-tool


aya-tool generate task_struct dentry > vmlinux.rs

# 生成包含 linux_binprm 结构体的 vmlinux.rs
aya-tool generate linux_binprm > vmlinux.rs

同时生成 linux_binprm 和 task_struct 结构体的绑定
aya-tool generate linux_binprm task_struct > vmlinux.rs

```