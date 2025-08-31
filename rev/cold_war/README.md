# Python Executable Reverse Engineering Write-up

## Challenge Information

**Title:** Cold Wars    
**Description:** I found this weird executable online, can you help me analyze what it is?

## Initial Analysis

### File Identification

The executable file's icon indicated that it was a compiled Python file.

### Extraction Process

![](<img/1.png>)

Following the guide from [How to Turn your .EXE files back to precious Python code! | Arcane Codex | Readers Hope](https://medium.com/readers-hope/how-to-turn-your-exe-files-back-to-precious-python-code-6c68c828d5aa), I used `pyinstxtractor` to extract the executable file.

## Decompilation

### Recovering Source Code

![](<img/2.png>)

In the extracted folder, there was a `chall.pyc` file. Using [PyLingual](https://pylingual.io/), I decompiled `chall.pyc` to `chall.py` to view the program's source code.

```python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: chall.py
# Bytecode version: 3.12.0rc2 (3531)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

import sys

def rc4(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    key = list(key)
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = (S[j], S[i])
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = (S[j], S[i])
        K = S[(S[i] + S[j]) % 256]
        out.append(b ^ K)
    return bytes(out)

xor = [212, 162, 242, 218, 101, 109, 50, 31, 125, 112, 249, 83, 55, 187, 131, 206]

def wrong() -> bytes:
    return bytes([167, 191, 210, 158, 15, 1, 107, 83, 104, 55, 183, 96, 124, 186, 180, 168])

def compute_b(launch_code: bytes):
    x = list(launch_code.ljust(16, b'\x00'))
    b = [None] * 16
    b[0] = x[2] ^ x[3] ^ x[4] ^ x[8] ^ x[11] ^ x[14]
    b[1] = x[0] ^ x[1] ^ x[8] ^ x[11] ^ x[13] ^ x[14]
    b[2] = x[0] ^ x[1] ^ x[2] ^ x[4] ^ x[5] ^ x[8] ^ x[9] ^ x[10] ^ x[13] ^ x[14] ^ x[15]
    b[3] = x[5] ^ x[6] ^ x[8] ^ x[9] ^ x[10] ^ x[12] ^ x[15]
    b[4] = x[1] ^ x[6] ^ x[7] ^ x[8] ^ x[12] ^ x[13] ^ x[14] ^ x[15]
    b[5] = x[0] ^ x[4] ^ x[7] ^ x[8] ^ x[9] ^ x[10] ^ x[12] ^ x[13] ^ x[14] ^ x[15]
    b[6] = x[1] ^ x[3] ^ x[7] ^ x[9] ^ x[10] ^ x[11] ^ x[12] ^ x[13] ^ x[15]
    b[7] = x[0] ^ x[1] ^ x[2] ^ x[3] ^ x[4] ^ x[8] ^ x[10] ^ x[11] ^ x[14]
    b[8] = x[1] ^ x[2] ^ x[3] ^ x[5] ^ x[9] ^ x[10] ^ x[11] ^ x[12]
    b[9] = x[6] ^ x[7] ^ x[8] ^ x[10] ^ x[11] ^ x[12] ^ x[15]
    b[10] = x[0] ^ x[3] ^ x[4] ^ x[7] ^ x[8] ^ x[10] ^ x[11] ^ x[12] ^ x[13] ^ x[14] ^ x[15]
    b[11] = x[0] ^ x[2] ^ x[4] ^ x[6] ^ x[13]
    b[12] = x[0] ^ x[3] ^ x[6] ^ x[7] ^ x[10] ^ x[12] ^ x[15]
    b[13] = x[2] ^ x[3] ^ x[4] ^ x[5] ^ x[6] ^ x[7] ^ x[11] ^ x[12] ^ x[13] ^ x[14]
    b[14] = x[1] ^ x[2] ^ x[3] ^ x[5] ^ x[7] ^ x[11] ^ x[13] ^ x[14] ^ x[15]
    b[15] = x[1] ^ x[3] ^ x[5] ^ x[9] ^ x[10] ^ x[11] ^ x[13] ^ x[15]
    return b

EYE = bytes([223, 176, 125, 151, 127, 31, 120, 248, 27, 91, 172, 37, 226, 24, 111, 234, 174, 97, 129, 135, 205, 130, 211, 149, 235, 225, 43, 54])

def main():
    print('\n      1. GLOBAL THERMONUCLEAR WAR\n      2. CHESS\n      3. CHECKERS\n    '.rstrip())
    choice = input('> ').strip()
    if choice != '1':
        print('\nONLY ONE GAME AVAILABLE.\n')
        return
    target = input('\nWHICH CITY DO YOU WANT TO TARGET? ').strip()
    print('\n PREPARING NUCLEAR STRIKE FOR', target.upper())
    launch_code = input('ENTER LAUNCH CODE: ').encode()
    h = list(wrong())
    h = [h[i] ^ xor[i] for i in range(16)]
    b = compute_b(launch_code)
    if b == h:
        flag = rc4(EYE, launch_code).decode(errors='strict')
        print('\n*** SIMULATION COMPLETED ***\n')
        print('A STRANGE GAME.')
        print('THE ONLY WINNING MOVE IS')
        print('NOT TO PLAY.\n')
        print('CONGRATULATIONS! YOU FOUND THE FLAG:\n')
        print(flag)
    else:
        print('\nIDENTIFICATION NOT RECOGNIZED BY SYSTEM')
        print('--CONNECTION TERMINATED--')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    sys.exit(1)
```

## Challenge Analysis

### Understanding the Program Flow

The program simulates a "Global Thermonuclear War" game and requires a correct launch code to reveal the flag. The key challenge is finding the correct `launch_code` value where:

```
compute_b(launch_code) == wrong() ^ xor
```

When this condition is met, the flag is decrypted using RC4 with the launch code as the key.

## Mathematical Solution

### Linear System in GF(2)

The `compute_b()` function creates a system of linear equations over GF(2) (binary field). Each row `b[i]` is an XOR of specific `x[j]` values, which can be represented as:

**A × x = h** (in GF(2))

Where:
- **A** is a 16×16 matrix (1 if `x[j]` is used in row i, 0 otherwise)
- **x** = bytes of launch_code  
- **h** = `wrong() ^ xor`

### Solution Implementation

```python
# target compute_b(launch_code) == (wrong() ^ xor)
def wrong() -> bytes:
    return bytes([167, 191, 210, 158, 15, 1, 107, 83, 104, 55, 183, 96, 124, 186, 180, 168])

xor = [212, 162, 242, 218, 101, 109, 50, 31, 125, 112, 249, 83, 55, 187, 131, 206]

# Matrix representation of compute_b function
rows = [
    [2,3,4,8,11,14],
    [0,1,8,11,13,14],
    [0,1,2,4,5,8,9,10,13,14,15],
    [5,6,8,9,10,12,15],
    [1,6,7,8,12,13,14,15],
    [0,4,7,8,9,10,12,13,14,15],
    [1,3,7,9,10,11,12,13,15],
    [0,1,2,3,4,8,10,11,14],
    [1,2,3,5,9,10,11,12],
    [6,7,8,10,11,12,15],
    [0,3,4,7,8,10,11,12,13,14,15],
    [0,2,4,6,13],
    [0,3,6,7,10,12,15],
    [2,3,4,5,6,7,11,12,13,14],
    [1,2,3,5,7,11,13,14,15],
    [1,3,5,9,10,11,13,15],
]

# Build coefficient matrix A
A = [[0]*16 for _ in range(16)]
for i, cols in enumerate(rows):
    for c in cols: 
        A[i][c] ^= 1

# Target vector
h = [a ^ b for a, b in zip(list(wrong()), xor)]

# Gaussian elimination in GF(2)
B = [row[:] for row in A]
rhs = h[:]
piv = [-1]*16
r = 0

for c in range(16):
    p = next((i for i in range(r,16) if B[i][c]), None)
    if p is None: 
        continue
    if p != r:
        B[r], B[p] = B[p], B[r]
        rhs[r], rhs[p] = rhs[p], rhs[r]
    piv[r] = c
    for i in range(16):
        if i != r and B[i][c]:
            B[i] = [x ^ y for x, y in zip(B[i], B[r])]
            rhs[i] ^= rhs[r]
    r += 1

# Back substitution
x = [0]*16
col2row = {piv[row]: row for row in range(16) if piv[row] != -1}
for col in range(15, -1, -1):
    if col not in col2row: 
        continue
    row = col2row[col]
    val = rhs[row]
    for j in range(col+1, 16):
        if B[row][j]: 
            val ^= x[j]
    x[col] = val

launch_code = bytes(x)
print(launch_code)
```

### Algorithm Explanation

1. **Matrix Construction:** Convert the `compute_b()` function into a coefficient matrix where each row represents the XOR relationships
2. **Gaussian Elimination in GF(2):** 
   - Select pivot for each column
   - Swap rows if needed
   - XOR the pivot row with other rows to eliminate the column
   - Apply the same operations to the right-hand side vector
3. **Back Substitution:** Solve for the 16 bytes of the launch code

## Flag Retrieval

![](<img/3.png>)

After obtaining the correct launch code from the mathematical solution, I input it into the original program (`chall.py`) to retrieve the flag.

## Flag

```
HiB25{SMT_S0LV3R_1S_M4G1C4L}
```

## Summary

This challenge demonstrated:

1. **Reverse Engineering** - Extracting and decompiling Python executables
2. **Mathematical Analysis** - Converting cryptographic functions to linear algebra problems
3. **Linear Algebra in GF(2)** - Solving systems of equations over binary fields
4. **Gaussian Elimination** - Implementing row reduction for binary matrices
5. **Cryptographic Understanding** - RC4 decryption with computed keys

The challenge required understanding that the `compute_b()` function creates a system of linear equations in the binary field GF(2), which can be solved using Gaussian elimination. The flag name `HiB25{SMT_S0LV3R_1S_M4G1C4L}` refers to SMT (Satisfiability Modulo Theories) solvers, highlighting the mathematical nature of the solution approach.