# Custom Virtual Machine Reverse Engineering Write-up

## Challenge Information

**Title:** HIBVM  
**Description:** A simple flag checker program, can you crack it open to get the flag?

## Initial Analysis

### Binary Examination

After importing the binary into Ghidra and decompiling it, the `main()` function appeared lengthy but had a clear pattern:

![](<img/1.png>)

1. Calls `get_seed_from_env()`
2. Calls `generate_keys`
3. Constructs an image heap via several `memcpy` operations
4. Calls `execute_vm(&local_938)` followed by `if ((int)local_938 == 1) puts("Correct!")`

### Flag Length Discovery

At the beginning of `main()`, there's `local_968 = 0x29`, which is used as the input length. Therefore, the flag is `0x29 = 41` bytes long.

### Memory Layout Analysis

![](<img/2.png>)

The `memcpy` operations reveal the memory layout:
- **Program VM (bytecode)** → copied to `pv` (offset 0)
- **User input** → copied to `pv + 0x1000`
- **Keys (array from generate_keys)** → copied to `pv + 0x2000`
- **Expected (reference array)** → copied to `pv + 0x3000`

## Environment and Key Generation

### Seed Discovery

![](<img/3.png>)

The `get_seed_from_env()` function reads the environment variable `WHUATISTISS`:
- If it starts with `0x`, it's parsed as hexadecimal
- If the environment variable doesn't exist, it falls back to `0xdeadbeef`

A note file `psnote.txt` was provided with the content `value = 0x8BADF00D`, which strongly suggests this is the correct seed.

### Key Generation Process

![](<img/4.png>)

The `generate_keys(base, len, seed)` function:
1. Calls `srand(seed)`
2. Loops through `rand()` calls
3. Stores the low 8 bits of each result as `keys[i]` for 41 bytes

## Virtual Machine Analysis

### VM Instruction Set

![](<img/5.png>)![](<img/6.png>)

The `execute_vm()` function contains a loop with switch opcodes:

- **0x01:** `reg[b] = imm32` (load immediate)
- **0x02:** `reg[b] = *(base + imm32)` (load 1 byte from image heap)
- **0x03:** `reg[b1] ^= reg[b2]` (XOR operation)
- **0x07:** `flag = (reg[b1] == reg[b2])` (comparison - 1 if equal, 0 otherwise)
- **0x05:** `if (flag == 0) ip += imm32` (conditional jump)
- **0x06:** `ip += imm32` (unconditional jump)
- **0x00:** halt

### VM Program Logic

The VM program, for each index `i` from 0 to 40:
1. Loads `input[i]` and `keys[i]`
2. Performs XOR operation
3. Compares the result against `expected[i]`
4. If they match, continues; if not, uses conditional jump to fail the verification

This means the VM enforces: **`input[i] ^ keys[i] == expected[i]`**

Therefore: **`input[i] = expected[i] ^ keys[i]`**

### Bytecode Generation Pattern

![](<img/8.png>)

In `main()`, there's a loop `for (local_970 = 0; local_970 < local_968; ...)` that constructs the `local_7f8` array (VM program) with a repeating pattern. For each `i`, the program fills a series of bytes equivalent to:

1. `0x02` (load) `regX ← base + (0x1000 + i)` (load input[i])
2. `0x02` (load) `regY ← base + (0x2000 + i)` (load keys[i])
3. `0x03` (xor) `regX ^= regY`
4. `0x01` (load imm) `regZ ← *(0x3000 + i)` (load expected[i])
5. `0x07` (cmp) `flag = (regX == regZ)`
6. `0x05` (jcc) if flag==0, jump to failure

## Flag Extraction

### Expected Array Recovery

![](<img/9.png>)

The call `memcpy(pv+0x3000, expected, 0x29)` in `main()` shows that `expected` is a symbol pointing directly to the reference array. Using Ghidra's double-click navigation, I located this data address and extracted the first 41 bytes.

### Solution Implementation

```python
import binascii, ctypes

N = 0x29
SEED = 0x8BADF00D
EXPECTED_HEX = "57b29f3ff0e005a3df7c98f97313a1a941f23d4aaeeefd9075ab40735d5cc6d1b429d88459d80cf78c"

def gen_keys(seed, n):
    libc = ctypes.CDLL("libc.so.6")
    libc.srand(ctypes.c_uint(seed))
    return bytes([libc.rand() & 0xff for _ in range(n)])

def main():
    expected = binascii.unhexlify(EXPECTED_HEX)
    keys = gen_keys(SEED, N)
    flag = bytes(e ^ k for e, k in zip(expected, keys))
    print(flag.decode("ascii"))

if __name__ == "__main__":
    main()
```

### Algorithm Summary

1. **Extract Expected Values:** Retrieve the 41-byte expected array from the binary
2. **Generate Keys:** Use the seed `0x8BADF00D` to generate the same 41-byte key sequence
3. **XOR Decryption:** Compute `flag[i] = expected[i] ^ keys[i]` for each byte
4. **ASCII Conversion:** Convert the resulting bytes to the flag string

## Flag

```
HiB25{V1rtu4L1z3d_C0d3_1S_R34LLY_AM4Z1NG}
```

## Summary

This challenge demonstrated:

1. **Virtual Machine Analysis** - Understanding custom VM instruction sets and execution models
2. **Memory Layout Reconstruction** - Mapping heap segments and data structures
3. **Cryptographic Analysis** - Recognizing XOR-based flag protection schemes
4. **Static Data Extraction** - Retrieving embedded constants from compiled binaries
5. **PRNG Understanding** - Replicating pseudorandom key generation

The challenge showcased how modern flag checkers can implement custom virtual machines to obfuscate their validation logic. However, by understanding the VM's instruction set and memory layout, the protection can be bypassed through static analysis and mathematical reversal of the encryption process.

The flag name `HiB25{V1rtu4L1z3d_C0d3_1S_R34LLY_AM4Z1NG}` appropriately celebrates virtualized code and VM-based protection schemes, which are increasingly common in modern reverse engineering challenges.