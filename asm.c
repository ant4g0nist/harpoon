// ignore this.
// objdump'd this bitch to dump raw shellcode
asm("mov $0x10c7c0bb0, %rax\njmp *%rax\n");
