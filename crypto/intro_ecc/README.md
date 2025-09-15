# ECDSA Nonce Reuse and Private Key Recovery Write-up

## Challenge Information

**Title:** Intro to ECC  
**Points:** 456  
**Author:** Yesver  
**Connection:** `nc ctf.m4.lu 65429`

## Description
*(No description provided)*

## Initial Analysis

### Service Architecture Examination

The challenge provides source code for the service running on `ctf.m4.lu:65429`, consisting of two key files: `app.py` and `signer.py`.

### App.py Analysis

Several critical functions were identified in `app.py`:

![](<img/1.png>)

1. **`get_flag()` function** - Returns the flag only if `signer.is_admin` is `True`

![](<img/2.png>)

2. **Account initialization** - Creates two accounts at startup:
   - Admin account with username pattern `administrator-(16 hex digits)`
   - Guest account with username `guest`

![](<img/3.png>)

3. **Initial message handling** - Calls `handle_send(admin, {'message': 'Welcome to Sign3r.'})` at connection start, providing a signed message from admin

![](<img/4.png>)

4. **`handle_receive()` function** - Accepts message and signature, converts hex signature to bytes, then finds the signer using `find_signer()`

### Critical Vulnerability Discovery

The `find_signer()` function iterates through all accounts, calls `verify()`, and if the message matches the target message, the server replaces the message with `get_flag(signer)` before printing the response. This reveals that:

- The server discloses the signer's username through the response
- The flag is only revealed if: signature is valid AND message matches target AND signer is admin

## Vulnerability Analysis

### ECDSA Nonce Vulnerability in signer.py

![](<img/5.png>)

The critical vulnerability lies in the `sign()` function's nonce generation. The nonce `k` is created by XORing:
- Integer representation of the username encoding
- A random 16-bit value

This creates a weak nonce with only 2^16 possible values, making brute force attacks feasible.

### Private Key Recovery Mathematics

With a known nonce `k`, the private key `d` can be recovered using the ECDSA equation:

```
d ≡ (s * k - z) * r^(-1) (mod n)
```

Where:
- `r`, `s` are signature components
- `z` is the message hash
- `n` is the curve order

### Attack Strategy

Since we know:
1. The admin's username (revealed by server response)
2. The signature components `(r, s, z)` for the "Welcome to Sign3r." message
3. The nonce generation method

We can brute force `k` in the 2^16 space by testing if `x(kG) mod n == r`, then recover the admin's private key.

## Solution Implementation

### JSON Communication Functions

```python
def recv_json(f):
    line = f.readline()
    if not line:
        raise EOFError("connection closed")
    return json.loads(line.decode().strip())

def send_json(s, obj):
    s.sendall((json.dumps(obj) + "\n").encode())
```

### Signature Parsing and Hash Function

```python
def der_to_rs(der_hex):
    der = bytes.fromhex(der_hex)
    r, s = sigdecode_der(der, n)
    return r, s

def hash_z(msg: str) -> int:
    return int.from_bytes(sha256(msg.encode()).digest(), "big")
```

### Nonce Brute Force Attack

```python
def brute_k_from_signature(username: str, r: int) -> int:
    uname_int = int.from_bytes(username.encode(), "big")
    for t in range(1<<16):
        k = uname_int ^ t
        R = k * G
        if (R.x() % n) == r:
            return k
    raise ValueError("k not found in 2^16 space")
```

### Private Key Recovery

```python
def recover_privkey_from_one_sig(username: str, msg: str, der_hex: str):
    r, s = der_to_rs(der_hex)
    z = hash_z(msg)
    k = brute_k_from_signature(username, r)
    rinv = pow(r, -1, n)
    d = ((s * k - z) * rinv) % n
    return d
```

### Message Signing with Recovered Key

```python
def sign_with_d(d: int, msg: str) -> str:
    sk = SigningKey.from_secret_exponent(d, curve=SECP256k1)
    sig = sk.sign_deterministic(msg.encode(), hashfunc=sha256, sigencode=sigencode_der)
    return sig.hex()
```

### Complete Exploit Script

```python
import socket, json
from hashlib import sha256
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigdecode_der, sigencode_der

HOST = "ctf.m4.lu"
PORT = 65429
G = SECP256k1.generator
n = G.order()

def main():
    s = socket.create_connection((HOST, PORT))
    f = s.makefile("rb")

    # Capture initial message and signature
    first = recv_json(f)
    assert first["type"] == "info"
    welcome_msg = first["data"]["message"]
    welcome_sig = first["data"]["signature"]

    # Send receive command to get admin username
    send_json(s, {"command":"receive","data":{"message":welcome_msg,"signature":welcome_sig}})
    
    # Extract admin username
    who = recv_json(f)
    admin_user = who["data"]["from"]

    # Brute force k and recover private key
    d = recover_privkey_from_one_sig(admin_user, welcome_msg, welcome_sig)

    # Sign target message with recovered key
    target = "I am administrator, give me the flag"
    forged_sig_hex = sign_with_d(d, target)

    # Retrieve flag
    send_json(s, {"command":"receive","data":{"message":target,"signature":forged_sig_hex}})
    resp = recv_json(f)
    print("FLAG:", resp["data"]["message"])

if __name__ == "__main__":
    main()
```

## Flag

```
HiB25{1e10c2905730d1744abd877153d82a82}
```

## Summary

This challenge demonstrated:

1. **ECDSA Nonce Security** - The critical importance of cryptographically secure nonce generation in ECDSA
2. **Private Key Recovery** - Mathematical techniques for recovering private keys from weak nonces
3. **Protocol Analysis** - Understanding multi-step authentication and authorization flows
4. **Brute Force Cryptanalysis** - Exploiting reduced entropy in cryptographic parameters

The challenge highlighted how a seemingly minor implementation flaw (XOR with 16-bit random values) can completely compromise an otherwise secure ECDSA implementation. The attack leveraged the deterministic relationship between nonce generation and username encoding, combined with the mathematical properties of ECDSA to recover the admin's private key and forge valid signatures.

The key insight was recognizing that the server's information disclosure (revealing signer usernames) combined with weak nonce generation created a complete attack path from initial reconnaissance to full private key recovery and signature forgery.