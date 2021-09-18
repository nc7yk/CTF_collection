from pwn import *
context(arch='amd64',endian='el',os='linux')
context.log_level='debug'
debug = 1
if debug == 1:
	p = process("./game")
else:
	p = remote("")

elf = ELF("./game",checksec=False)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)

p.sendafter("cmd> ",':aaaaa')
gdb.attach(p)
p.recvuntil("cmd> ")

p.interactive()
