---
title: "02.2 常见 Shellcode 场景与写法框架"
date: 2026-11-25 03:00:00 +0800
description: "梳理 Pwn 中常见的五类 Shellcode 使用场景、约束条件与结构框架，方便按题型自行填入具体汇编或 pwntools 代码。"
categories: [Pwn笔记, 第02章 Shellcode]
tags: [shellcode, seccomp, orw, pwntools]
---

本文接 [02.1 Pwn 中的 Shellcode 工具与基础汇编写法](/posts/shellcode-tools/)，按题目里最常碰到的约束条件整理出几套结构框架。每节只列出前提条件、设计思路和代码骨架，具体指令和模板内容留给你自己按环境填。

## 场景一：无沙箱、空间充足

- **常见前提**：栈或某块 `mmap` 区域具备 `RWX` 权限，没有开启 `seccomp`，读入空间充裕且没有严格的坏字符限制。
- **结构思路**：拿到可写入且可跳转的目标地址后，直接写入目标功能指令并劫持控制流跳入。重点只需核对目标地址是否准确、总字节数是否越界。

```python
from pwn import *

context.arch = "amd64"
# TODO: 加载 ELF / 连接本地或远程进程

# TODO: 构造目标汇编或调用模板，编译为字节
sc = b""

# TODO: 检查长度与截断字符
# assert len(sc) <= ...

# TODO: 发送 payload 并进入交互或接收输出
```

## 场景二：开启 `seccomp` 禁用 `execve`（ORW 结构）

- **常见前提**：用 `seccomp-tools dump` 看到 `execve` / `execveat` 被禁止，但文件与 I/O 类系统调用可用。
- **结构思路**：目标从“启动程序”换成“读取文件内容并输出”，固定拆成三步：**Open → Read → Write**。注意前一步返回的 `fd` 在 `rax` 里，下一步赋调用号前必须先转存到别的寄存器；读入的数据可以直接借用当前栈顶 `rsp` 或已知可写地址当缓冲区。

```nasm
; === Step 1: 打开目标文件 ===
; TODO: 准备路径字符串指针（注意长度超过 8 字节时分段压栈或 rel 寻址）
; TODO: 设置系统调用号与只读参数，触发 syscall

; === Step 2: 读取文件内容 ===
; TODO: 把上一步 rax 返回的 fd 转存到 rdi（别留在 rax 里被冲掉）
; TODO: 设置接收缓冲区地址（如 rsp）与读取长度，rax = sys_read，触发 syscall

; === Step 3: 输出到标准输出 ===
; TODO: 设置 fd = 1，buf = 上一步的缓冲区，count = 读取字节数，rax = sys_write，触发 syscall
```

## 场景三：缓冲区极短（两阶段 Staged 结构）

- **常见前提**：漏洞点单次只允许写十几到三十几字节，完整逻辑放不下，但注入位置本身可写可执行，且允许后续继续输入。
- **结构思路**：拆成两段接力。第一段只写一个极短的 `sys_read` 引导段，把更长的第二段直接读到紧随其后的地址（或指定 `RWX` 地址），`read` 返回后顺序往下执行。动手前先用 `gdb` 看一眼跳入第一段时各寄存器的初始值——往往能直接复用 `rsi`/`rdi`/`rdx` 里的残留值，省掉好几条赋值指令。

```python
from pwn import *

context.arch = "amd64"

# Stage 1: 极短的 read 引导代码，尽量复用入口时的寄存器初值
stage1 = asm("""
    # TODO: 设好 fd = 0，buf = 接续执行地址，count = 足够长度
    # TODO: rax = 0 (sys_read)，执行 syscall
""")

# Stage 2: 真正要执行的主体字节
stage2 = b""

# TODO: 检查 len(stage1) 是否满足第一轮上限
# TODO: 先发送 stage1，待程序停在 read 时再发送 stage2
```

## 场景四：坏字符或字符集限制（过滤绕过结构）

- **常见前提**：输入走 `strcpy`（禁 `\x00`）、`gets`/`scanf`（禁 `\x00`/`\n`/空白符），或者程序执行前校验输入只允许可见 ASCII / 字母数字字符。
- **结构思路**：先明确到底禁了哪些字节，再把校验写进脚本断言里。只禁 `\x00`/`\n` 时，用 [02.1](/posts/shellcode-tools/) 的 `xor` 清零、`push imm8; pop`、`shr` 消零做局部替换即可；如果卡到纯字母数字等极窄字符集，只能选用编码落在允许区间内的指令（或自解码器结构把主体在运行时还原）。

```python
BAD_BYTES = {0x00, 0x0a}  # TODO: 按题目实际过滤条件增删

# TODO: 编写或编码生成字节序列
sc = b""

bad = [b for b in sc if b in BAD_BYTES]
assert not bad, f"found bad bytes: {[hex(x) for x in bad]}"
```

## 场景五：`seccomp` 变体与替代思路速查

遇到某几个常见系统调用被单独封掉时，先用 `seccomp-tools` 确认边界，再按下面方向替换：

| 被禁用的调用 | 常见替代方向 | 说明 |
| --- | --- | --- |
| `open` | `openat` | 注意第 1 个参数传 `AT_FDCWD`（`-100`），路径在第 2 个参数。 |
| `read` / `write` | `pread64` / `pwrite64`、`sendfile` | `sendfile(1, fd, 0, size)` 可直接把文件拷贝到 stdout，少一次中间缓冲。 |
| `execve` | `execveat` 或改走 ORW | 先确认是不是只漏禁了其中一个。 |
| 所有输出调用 | 侧信道盲注 | 读入内存后逐字节比较，靠死循环或立即崩溃区分结果。 |

---

## 写前检查清单

- **先看规则再动笔**：用 `readelf -l` 和 `seccomp-tools dump` 确认内存权限与可用 `syscall`，别凭经验猜。
- **先看现场寄存器**：`gdb` 在跳转到输入点前断下来看一眼寄存器初值，短空间场景经常能省出一半指令。
- **先打印反汇编再发**：每次改动后固定跑一遍 `print(disasm(sc))` 和坏字符断言，确认长度和字节都干净再连靶机。
