---
title: "02.1 Shellcode 汇编语法与常用工具"
date: 2026-11-25 02:00:00 +0800
description: "介绍编写位置无关汇编时的 Intel/AT&T 语法差异、NASM 常用伪指令与符号，以及编译、提取字节和检查约束的常用工具。"
categories: [Pwn笔记, 第02章 Shellcode]
tags: [shellcode, assembly, nasm, objdump]
---

本文接 [02.0 Shellcode 概述](/posts/shellcode/)，把动手写位置无关汇编前需要用到的语法规则、常见伪指令符号，以及汇编/反汇编/检查工具链串一遍。后面用一段只做输出和正常退出的最小系统调用程序演示整个流程。

## Intel 语法与 AT&T 语法

Linux 下最常见两套 x86-64 汇编风格：写独立片段常用 **Intel 语法**（NASM、`pwntools`、`objdump -M intel`），GCC 和 `as` 默认则是 **AT&T 语法**。对照看几条最容易混的规则：

| 差异点 | Intel 语法（NASM） | AT&T 语法（GAS / `as`） |
| --- | --- | --- |
| 操作数顺序 | `目标, 源`：`mov rax, 1` | `源, 目标`：`movq $1, %rax` |
| 寄存器与立即数 | 无前缀：`rax`、`1` | 寄存器带 `%`，立即数带 `$` |
| 指令宽度后缀 | 由操作数决定：`mov eax, 1` | 指令带后缀 `b/w/l/q`：`movl $1, %eax` |
| 内存寻址 | `[基址 + 变址*比例 + 偏移]` | `偏移(基址, 变址, 比例)` |

写笔记和看反汇编时建议统一用 Intel 语法，和 IDA / `pwndbg` 的默认视图一致，不容易把源和目标看反。

## NASM 常用伪指令与符号

写位置无关的纯汇编代码通常用 NASM，几个高频关键字和符号的作用如下：

- **`bits 64`**：指定按 x86-64 模式生成机器码。用 `-f bin` 直接输出裸二进制文件时必须加上，否则默认按 16 位编码。
- **`section .text` / `global _start`**：生成完整 ELF 程序测试时，用来声明代码段和链接器入口符号 `_start`。
- **`db` / `dw` / `dd` / `dq`**：分别在当前位置按 1、2、4、8 字节写入原始数据，例如 `msg: db "hi", 0x0a`（`0x0a` 是换行符 `'\n'`）。
- **`equ`**：定义编译期常量，不占实际指令或数据空间。
- **`$` 与 `$$`**：`$` 代表当前行所处的汇编地址，`$$` 代表当前段（section）的起始地址。最常见的用法是 `len equ $ - msg`，用当前地址减去 `msg` 的起始地址，直接算出字节长度。
- **`rel`**：放在内存寻址中（如 `lea rsi, [rel msg]`），强制 NASM 生成基于 `rip` 的相对偏移寻址，不依赖固定装载地址。
- **局部标签（`.loop`）**：以 `.` 开头的标签只归属于上面最近一个非点号全局标签，适合多段代码里反复用 `.done`、`.loop` 而不会重名。

## 常用工具链

### 汇编、链接与提取字节

写好的 `.asm` 文件常见两种用法：编成完整 ELF 跑起来验证逻辑，或者只抽出代码字节看编码长度与坏字符。

```bash
# 1. 编成完整 ELF 可执行程序，方便直接运行或进 gdb 调试
nasm -f elf64 demo.asm -o demo.o
ld demo.o -o demo

# 2. 直接输出不带 ELF 头的纯机器码文件（需在源码开头写 bits 64）
nasm -f bin demo.asm -o demo.bin

# 3. 如果已经编出了 ELF，也可以只抽其中的 .text 段字节
objcopy -O binary --only-section=.text demo demo.bin
```

### 反汇编与查看机器码

看一段汇编到底编出了哪些字节、有没有夹带 `0x00` 或 `0x0a`，最直接的是反汇编：

```bash
# 查看 ELF 文件的汇编与对应机器码（记得加 -M intel）
objdump -d -M intel demo

# 查看纯二进制文件（无 ELF 头）的反汇编
objdump -D -b binary -m i386:x86-64 -M intel demo.bin

# NASM 自带的裸二进制反汇编器，命令更短
ndisasm -b 64 demo.bin
```

### 检查可执行权限与沙箱规则

动手分析题目环境时，下面两个工具用来确认保护边界：

```bash
# 查看栈段 GNU_STACK 标志（RW 表示不可执行，RWE 表示栈可执行）
readelf -l ./chal

# 打印程序加载的 seccomp 规则，看哪些系统调用被禁止或放行
seccomp-tools dump ./chal
```

### 用 `pwntools` 快速验单条指令

在 Python 里临时确认某条指令占几字节、会编出什么十六进制值，不用每次都建 `.asm` 文件：

```python
from pwn import *

context.arch = "amd64"       # 必须显式指定，pwntools 默认是 32 位 i386
code = asm("xor eax, eax; mov al, 1")
print(code.hex(), len(code)) # 31c0b001 4
print(disasm(code))
```

## 工具链最小示例

下面用一段向标准输出打印 `"hi\n"` 并正常退出的 `demo.asm` 走一遍编译与检查过程：

```nasm
bits 64
global _start

section .text
_start:
    mov rax, 1              ; 调用号 1: sys_write
    mov rdi, 1              ; 参数 1: fd = 1 (stdout)
    lea rsi, [rel msg]      ; 参数 2: rip 相对寻址取字符串
    mov rdx, msg_len        ; 参数 3: 长度
    syscall

    mov rax, 60             ; 调用号 60: sys_exit
    xor rdi, rdi            ; 参数 1: status = 0
    syscall

msg:
    db "hi", 0x0a
msg_len equ $ - msg
```

把 `msg` 紧接在 `syscall` 后面的同一个 `.text` 段里，这样无论编成 ELF 还是用 `nasm -f bin` 直接输出裸字节，相对偏移都能对齐。

用 `nasm -f elf64` 编译链接后运行会打印 `hi`，再看 `objdump -d -M intel demo` 的前几行：

```text
401000: b8 01 00 00 00          mov    eax,0x1
401005: bf 01 00 00 00          mov    edi,0x1
40100a: 48 8d 35 13 00 00 00    lea    rsi,[rip+0x13]
401011: ba 03 00 00 00          mov    edx,0x3
401016: 0f 05                   syscall
```

可以看到虽然这段汇编能跑通、也是位置无关的，但机器码里全是 `00` 字节——这正是为什么实际受限场景中需要改写指令形式，下一篇 [02.2 Shellcode 常用汇编写法](/posts/shellcode-patterns/) 会具体拆这些局部替代写法。

---

## 常见踩坑小结

- **`pwntools` 忘了设 `context.arch = "amd64"`**：默认按 32 位 `i386` 汇编，遇到 `rax`、`rsi` 或 `syscall` 会直接报错或编出错误指令。
- **`nasm -f bin` 忘了写 `bits 64`**：没有 `bits 64` 时 NASM 按 16 位实模式编码，生成的机器码长度和寄存器操作全乱。
- **`objdump` 忘了加 `-M intel`**：默认以 AT&T 语法输出，方向和 NASM 源码反着来，对照调试很容易看错。
- **用 `nasm -f bin` 时分了 `.data` 段**：平铺二进制没有链接器重定位段布局，数据尽量直接放在 `.text` 尾部并用 `rel` 寻址，或者压栈构造。
