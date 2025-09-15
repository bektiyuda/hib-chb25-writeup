# Textbook RSA Character-by-Character Brute Force Write-up

## Challenge Information

**Title:** Loop  
**Description:** *(No description provided)*

## Initial Analysis

### File Structure Examination

The challenge provided two files: `out.zip` and `chall.zip`. When both are extracted, these files are interconnected and provide the complete challenge context.

### Source Code Analysis

`chall.zip` contains the source code of an RSA encryption program that operates on the FLAG with the following process:

![](<img/1.png>)

1. **RSA Key Generation:** Creates a single 2048-bit RSA key pair

![](<img/2.png>)

2. **Character Processing:** Each character from the FLAG is salted using the pattern `"_SALTED_{:02d}"` via `Config.generate_salt()`

![](<img/3.png>)

3. **Textbook RSA Encryption:** The message `(character + salt)` is encrypted using `public_key._encrypt()`

4. **Output Generation:** Encrypted data is written to `encrypted_flag.bin` and public key to `out/public_key.pem`

### Vulnerability Identification

The critical vulnerability lies in the use of textbook RSA via the internal `._encrypt()` method, which performs raw RSA without padding. This creates a scenario where:

- Encryption follows the formula: `c = m^e mod n`
- Each message `m` is extremely small: `(single_byte_character) + "_SALTED_XX"`
- The search space per block is minimal (95 printable ASCII characters or maximum 256 possible first bytes)

## Vulnerability Analysis

### Textbook RSA Weakness

With textbook RSA, the small message space makes brute force attacks feasible. For each encrypted block, we can:

1. Generate candidate messages by trying all possible characters
2. Apply the same salt pattern used in encryption
3. Compute `pow(candidate_message, e, n)` and compare with the ciphertext
4. When they match, we've found the original character

### Salt Pattern Understanding

The salt format `"_SALTED_{:02d}"` means:
- First character gets salt `"_SALTED_01"`
- Second character gets salt `"_SALTED_02"`
- And so on...

This predictable pattern allows us to reconstruct the exact message format for each position.

## Solution Implementation

### RSA Parameter Extraction

```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long

# Extract RSA parameters
with open('out/public_key.pem', 'rb') as f:
    key = RSA.import_key(f.read())
n, e = key.n, key.e
modulus_size = (n.bit_length() + 7) // 8
```

### Ciphertext Block Processing

```python
# Read and split encrypted data into blocks
with open('out/encrypted_flag.bin', 'rb') as f:
    data = f.read()
blocks = [data[i:i+modulus_size] for i in range(0, len(data), modulus_size)]
```

### Character Recovery Algorithm

```python
SALT_FMT = "_SALTED_{:02d}"
PRINTABLE = [chr(i) for i in range(32, 127)]
flag_chars = []

for idx, block in enumerate(blocks):
    c_int = bytes_to_long(block)
    salt = SALT_FMT.format(idx+1)
    found = None
    
    # Try all printable ASCII characters
    for ch in PRINTABLE:
        m_int = bytes_to_long((ch + salt).encode())
        if pow(m_int, e, n) == c_int:
            found = ch
            break
    
    # Try all possible bytes if not found in printable range
    if found is None:
        for b in range(256):
            m_int = bytes_to_long(bytes([b]) + salt.encode())
            if pow(m_int, e, n) == c_int:
                found = bytes([b]).decode('latin1')
                break
    
    flag_chars.append(found if found else '?')

flag = ''.join(flag_chars)
print("Recovered flag:", flag)
```

### Complete Exploit Script

```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long

SALT_FMT = "_SALTED_{:02d}"

# Extract RSA parameters from public key
with open('out/public_key.pem', 'rb') as f:
    key = RSA.import_key(f.read())
n, e = key.n, key.e
modulus_size = (n.bit_length() + 7) // 8

# Read encrypted flag and split into blocks
with open('out/encrypted_flag.bin', 'rb') as f:
    data = f.read()
blocks = [data[i:i+modulus_size] for i in range(0, len(data), modulus_size)]

# Define character search space
PRINTABLE = [chr(i) for i in range(32, 127)]
flag_chars = []

# Recover each character through brute force
for idx, block in enumerate(blocks):
    c_int = bytes_to_long(block)
    salt = SALT_FMT.format(idx+1)
    found = None
    
    # Try all printable ASCII characters
    for ch in PRINTABLE:
        m_int = bytes_to_long((ch + salt).encode())
        if pow(m_int, e, n) == c_int:
            found = ch
            break
    
    # Try all possible bytes if not found in printable range
    if found is None:
        for b in range(256):
            m_int = bytes_to_long(bytes([b]) + salt.encode())
            if pow(m_int, e, n) == c_int:
                found = bytes([b]).decode('latin1')
                break
    
    flag_chars.append(found if found else '?')

flag = ''.join(flag_chars)
print("Recovered flag:", flag)
```

## Flag

```
HIB25{d3c1c9ed34cbc35e88eb89446c175fa5}
```

## Summary

This challenge demonstrated:

1. **Textbook RSA Vulnerability** - Exploiting unpadded RSA encryption with small message spaces
2. **Brute Force Cryptanalysis** - Systematically testing all possible plaintexts against known ciphertext
3. **Salt Pattern Analysis** - Understanding predictable salt generation for message reconstruction
4. **Modular Arithmetic** - Using Python's `pow()` function for efficient modular exponentiation

The challenge highlighted the critical importance of proper padding schemes in RSA implementations. Without padding, small message spaces become vulnerable to brute force attacks, especially when the message format is predictable. The use of character-by-character encryption with known salt patterns made it possible to recover the entire flag through exhaustive search of the limited character space.

The key insight was recognizing that each encrypted block represented a single character plus a predictable salt, making the effective search space small enough for practical brute force attacks despite the 2048-bit RSA key.