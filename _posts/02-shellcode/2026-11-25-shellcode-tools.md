---
title: "02.1 Pwn 中的 Shellcode 工具与基础汇编写法"
date: 2026-11-25 02:00:00 +0800
description: "介绍 Pwn 常用的 pwntools（asm/disasm/shellcraft）用法、看懂和精简 x86-64 汇编的基础写法，以及检查沙箱与坏字符的方法。"
categories: [Pwn笔记, 第02章 Shellcode]
tags: [shellcode, pwntools, shellcraft, assembly]
---

本文接 [02.0 Shellcode 概述](/posts/shellcode/)。做 Pwn 题一般不从零用 `nasm` 配链接器手搓 ELF，而是直接用 `pwntools` 里的工具拼装、反汇编和排查长度与坏字符；同时需要看得懂常见的 x86-64 汇编写法，才能定位为什么某段生成结果会超长或带出 `\x00`。下面把工具用法和基础汇编块合在一篇讲（文内示例统一用输出字符串和正常退出演示）。

## `pwntools` 核心三件套

### 1. 先设 `context.arch`

用 `pwntools` 处理汇编前，第一行先把架构设成 64 位：

```python
from pwn import *

context.arch = "amd64"
context.os = "linux"
```

`pwntools` 默认架构是 32 位 `i386`。忘了改 `amd64` 时，遇到 `rax`、`rsi` 或 `syscall` 会直接报错，或者把指令编成 32 位机器码。

### 2. `asm()` 与 `disasm()`

- `asm(代码字符串)`：把 Intel 风格汇编文本编成机器码 `bytes`，支持多条指令用 `;` 或换行分隔。
- `disasm(字节串)`：把一段机器码反汇编回带偏移和十六进制编码的文本，方便逐条排查长度和坏字符。

```python
code = asm("xor eax, eax; mov al, 1")
print(code.hex(), len(code))    # 31c0b001 4
print(disasm(code))
```

拿到一段机器码后，通常顺手检查三件事：总字节数是否超过 `read` 上限、是否含 `\x00`（截断 C 字符串）、是否含 `\n`（`0x0a`，会被 `gets`/`fgets`/`scanf` 截断）：

```python
assert len(code) <= 64
assert b"\x00" not in code and b"\n" not in code
```

### 3. `shellcraft` 怎么用与怎么查

`shellcraft` 是 `pwntools` 内置的汇编模板库，按架构和系统分模块，64 位 Linux 下主要用 `shellcraft.amd64.linux`。

最容易踩的一个点是：**`shellcraft.xxx()` 返回的是汇编文本（`str`），不是机器码（`bytes`）**，必须外面再包一层 `asm(...)` 才能发送。

写脚本前建议先 `print` 出来看一遍，或者在命令行用 `pwn shellcraft` 查可用模板与参数说明：

```bash
# 列出 amd64 Linux 下所有可用模板
pwn shellcraft -l amd64.linux

# 查看单个模板的源码和注释
pwn shellcraft amd64.linux.echo
```

Python 里用输出和退出做个最小演示：

```python
from pwn import *

context.arch = "amd64"

asm_src = shellcraft.echo("hi\n") + shellcraft.exit(0)
print(asm_src)          # 先看生成的汇编文本，确认每一步在干什么

sc = asm(asm_src)       # 再汇编成字节
print(len(sc), sc.hex())
```

用 `shellcraft` 时仍然要会看汇编，原因有两个：一是通用模板有时偏冗长，碰到只给三四十字节读入空间的题目会塞不下；二是某些参数写法可能带出 `0x0a` 等坏字符，看懂生成的源码才知道该改哪一行。

## Pwn 常用的基础汇编写法

阅读 `shellcraft` 输出或自己精简短片段时，核心就是下面这四组基础写法。

### 1. Intel 语法速览

`pwntools`、`objdump -M intel` 和 `pwndbg` 都用 Intel 语法：

- 操作数顺序永远是 **`目标, 源`**（`mov rdi, rax` 表示把 `rax` 的值放进 `rdi`）。
- 寄存器和常数不带前缀，`[rsp]` 表示把 `rsp` 当作指针解引用取内存。

### 2. 清零与写小正整数（避开 `\x00`）

直接写 `mov rax, 0` 或 `mov rax, 1` 会编出 `b8 01 00 00 00`，带出一串 `00`。常见替代写法：

- **清零用 `xor eax, eax`**（`31 c0`，2 字节）：x86-64 下写 32 位寄存器会自动把对应 64 位寄存器的高 32 位一并清零，效果等价于 `xor rax, rax`，还省掉 1 字节 `REX.W` 前缀。
- **顺手清零 `rdx` 用 `cdq`**：只要 `eax` 当前是非负数（最高位为 `0`），1 字节指令 `cdq`（`99`）就能把 `edx`/`rdx` 清成 `0`。
- **赋值 `1`\~`127` 用 `push imm8; pop reg`**：例如 `push 1; pop rax`（`6a 01 58`）只占 3 字节且无 `\x00`；或者先 `xor eax, eax` 再 `mov al, 1`（4 字节）。注意 `push imm8` 会按**有符号 8 位整数**扩展到 64 位，超过 `127`（如 `0x80`）会变成负数。

### 3. 三种位置无关数据寻址

独立运行的代码片段不能写死 `.rodata` 的绝对地址，数据通常靠下面三种方式定位：

- **`rip` 相对寻址（`lea reg, [rel label]`）**：最干净，但要注意如果 `label` 放在指令后面不远处，正偏移高位会带出 `00`；把数据放在指令**前面**并用 `jmp` 跳过，负偏移高位全是 `ff`，就能避开 `00`。
- **压栈构造短字符串（`push` + `mov reg, rsp`）**：≤ 8 字节的字符串可以直接按小端序压栈，此时 `rsp` 就是字符串首地址。如果末尾需要 `\x00` 又不能在指令里出现 `00`，可以先在最高位填一个非零占位字节，再用 `shr` 右移挤掉占位字节、自动在高位补出 `00`：

```nasm
mov eax, 0x0a696841   ; 小端序字节为 'A', 'h', 'i', '\n'（无 \x00）
shr eax, 8            ; 变成 0x000a6968，栈上即 "hi\n\x00"
push rax
mov rsi, rsp          ; rsi 指向栈顶的 "hi\n"
```

- **`jmp` / `call` / `pop` 跳板**：适合自带较长数据。顺序必须是 **`jmp` 在前、`call` 在后往低地址回跳**——`call` 把下一行数据地址压栈后，目标位置直接 `pop rsi` 就能拿到指针；往回跳偏移为负，能避开 `call` 正向短跳编出的 `00`。

### 4. `syscall` 前后的寄存器保存

串多个系统调用时，硬件和 ABI 有三条硬规则要记住：

- **`rcx` 和 `r11` 会被覆盖**：执行 `syscall` 时 CPU 自动把返回地址存进 `rcx`、标志位存进 `r11`，临时数据不要放这两个寄存器里跨 `syscall`。
- **第 4 个参数放在 `r10`**：不是普通函数调用里的 `rcx`。
- **返回值留在 `rax`**：前一个系统调用返回的句柄或长度如果后面还要用，必须先 `mov` 或 `xchg` 转存到安全寄存器（如 `rdi`、`r12`），再给 `rax` 赋下一个调用号。

## 综合示例：组装并检查一段无空字节代码

把上面的 `pwntools` 工具和基础汇编写法合在一起，组装一段不含 `0x00` 的 `sys_write(1, "hi\n", 3)` + `sys_exit(0)` 并打印反汇编结果：

```python
from pwn import *

context.arch = "amd64"

sc = asm("""
    mov eax, 0x0a696841   /* "Ahi\n"，避开直接写 0x00 */
    shr eax, 8            /* 变为 0x000a6968 -> "hi\n\x00" */
    push rax
    mov rsi, rsp          /* buf = rsp */

    push 1
    pop rax               /* 调用号 1: sys_write */
    mov edi, eax          /* fd = 1 (stdout) */
    xor edx, edx
    mov dl, 3             /* count = 3 */
    syscall

    xor edi, edi          /* status = 0 */
    push 60
    pop rax               /* 调用号 60: sys_exit */
    syscall
""")

assert b"\x00" not in sc
print(f"len = {len(sc)} bytes")
print(disasm(sc))
```

这段代码总共 27 字节，先准备 `rsi` 再写 `rax = 1`，避免 `shr` 冲掉调用号。用 `disasm(sc)` 可以直接核对每条指令的机器码里有没有意外的 `\x00` 或 `\n`。

## 配合检查环境的两个命令行工具

正式写 exp 前，顺手用这两个命令确认二进制本身的保护边界：

```bash
# 查看栈段 GNU_STACK 权限（RW 表示开启 NX 不可执行，RWE 表示栈可执行）
readelf -l ./chal

# 打印 seccomp 沙箱规则，确认哪些 syscall 被禁止或放行
seccomp-tools dump ./chal
```

---

## 常见踩坑小结

- **忘了设 `context.arch = "amd64"`**：`pwntools` 默认按 32 位编码，寄存器和 `syscall` 全会出错。
- **直接发送 `shellcraft.xxx()` 的返回值**：它返回的是汇编字符串，不包一层 `asm(...)` 发出去的是 ASCII 文本不是机器码。
- **`xor al, al` 只清低 8 位**：高 56 位还留着旧值，清零整个寄存器必须写 `xor eax, eax`。
- **`push` 超过 `127` 会符号扩展**：`push 0x80` 弹出来会变成 `0xffffffffffffff80`，大于 `127` 的正整数要用移位或寄存器拼接。
- **跨过 `syscall` 存临时值在 `rcx`/`r11`**：`syscall` 返回后这两个寄存器会被硬件覆盖，值就丢了。
