# Gatekeeper - Authentication Token XOR Manipulation Write-up

## Challenge Information

**Title:** Gatekeeper  
**Points:** 356  
**Author:** Yesver  
**Connection:** https://gatekeeper.ctf.m4.lu/

## Description
*(No description provided)*

## Initial Analysis

### Web Application Exploration

![](<img/1.png>)

The challenge provides a website URL and its source code. After registering and logging in, the website redirects to `/dashboard` where user information is displayed, including:

- **Access Level:** Shows as "Standard" for registered users
- **User Access:** Inaccessible for standard users  
- **auth_token cookie:** Set upon successful login

### Source Code Analysis

#### Admin Account Discovery

![](<img/2.png>)

In the `create_app()` function, the application automatically creates an admin account if one doesn't exist during website initialization. This reveals the existence of a privileged account.

#### Flag Access Requirement

![](<img/3.png>)

The `/dashboard` endpoint code reveals that the FLAG can only be obtained if the user's role is "admin". This provides a clear attack target: escalate privileges from standard user to admin.

## Vulnerability Analysis

### Authentication Token Structure

![](<img/4.png>)

The authentication token is created through the `create_token()` function in `services.py`:

1. **PKCS#7 Padding:** User data from `/login` is padded to 64 bytes using PKCS#7 padding
2. **XOR Encryption:** Padded data is XORed byte-by-byte with a repeating key
3. **Base64URL Encoding:** The result is encoded using base64url format

### XOR Cipher Vulnerability

The token generation uses a simple XOR cipher with the following properties:
- **Malleability:** XOR ciphers are malleable - modifying the ciphertext predictably changes the plaintext
- **Known Plaintext:** We know our username and can predict the padded format
- **Target Format:** We know the target format for admin authentication

### Attack Strategy

Since we have:
- Our current token `C = pad(username) XOR K`  
- Knowledge of our username (plaintext `P`)
- Target username "admin" (target plaintext `P'`)

We can forge an admin token using: `C' = C XOR (pad(P) XOR pad(P'))`

When decrypted, this yields: `P' = pad("admin", 64)`

## Solution Implementation

### Padding and Encoding Functions

```python
import base64

BLOCK = 64

def pkcs7_pad(b, block=BLOCK):
    padlen = block - (len(b) % block)
    return b + bytes([padlen])*padlen

def b64u_dec(s):
    s = s.strip()
    # Normalize padding
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s)

def b64u_enc(b):
    return base64.urlsafe_b64encode(b).decode()
```

### Token Forgery Function

```python
def forge_token(token_b64, username, target_username="admin"):
    # Decode the current token
    C = b64u_dec(token_b64)
    
    # Create padded versions of current and target usernames
    P  = pkcs7_pad(username.encode(), BLOCK)
    Pp = pkcs7_pad(target_username.encode(), BLOCK)
    
    if len(C) != len(P):
        raise ValueError("Ciphertext length not match")
    
    # Calculate the XOR delta between plaintexts
    delta = bytes([a ^ b for a,b in zip(P, Pp)])
    
    # Apply delta to create forged token
    Cp = bytes([c ^ d for c,d in zip(C, delta)])
    
    return b64u_enc(Cp)
```

### Complete Exploit Script

```python
import base64

BLOCK = 64

def pkcs7_pad(b, block=BLOCK):
    padlen = block - (len(b) % block)
    return b + bytes([padlen])*padlen

def b64u_dec(s):
    s = s.strip()
    # normalize padding
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s)

def b64u_enc(b):
    return base64.urlsafe_b64encode(b).decode()

def forge_token(token_b64, username, target_username="admin"):
    C = b64u_dec(token_b64)
    P  = pkcs7_pad(username.encode(), BLOCK)
    Pp = pkcs7_pad(target_username.encode(), BLOCK)
    if len(C) != len(P):
        raise ValueError("Ciphertext length not match")
    delta = bytes([a ^ b for a,b in zip(P, Pp)])
    Cp = bytes([c ^ d for c,d in zip(C, delta)])
    return b64u_enc(Cp)

# Replace with your actual username and token
username = "testwuhib"
token    = "iMhIpPcf3LiSsy-rsjvzE11LdxIxZcLzOVEAmd98lzYrpglDd9WDDuyObmUt-jRWUgpnMW1oqmTOeP26b3c6tg=="

admin_token = forge_token(token, username, "admin")
print("New auth_token:")
print(admin_token)
```

### Exploitation Process

1. **Register and Login:** Create a standard user account and obtain the auth_token
2. **Token Analysis:** Extract the base64url-encoded token from cookies
3. **Forge Admin Token:** Use the XOR manipulation technique to create an admin-equivalent token
4. **Cookie Replacement:** Replace the auth_token cookie with the forged token
5. **Access Dashboard:** Visit `/dashboard` to retrieve the flag

## Flag

```
HiB25{33024bc7a8e1afe1e8a1cb2112611fed}
```

## Summary

This challenge demonstrated:

1. **XOR Cipher Malleability** - Exploiting the mathematical properties of XOR operations for ciphertext manipulation
2. **Authentication Bypass** - Escalating privileges through cryptographic token forgery
3. **Padding Oracle Concepts** - Understanding PKCS#7 padding in cryptographic contexts
4. **Web Application Security** - Analyzing authentication mechanisms and privilege escalation vectors

The challenge highlighted the dangers of using simple XOR ciphers for authentication tokens. The malleability property of XOR encryption allows attackers to predictably modify ciphertexts when they know or can guess portions of the plaintext. Combined with a predictable padding scheme, this creates a complete authentication bypass vulnerability.

The key insight was recognizing that XOR encryption with known plaintext patterns enables controlled ciphertext manipulation, allowing privilege escalation from standard user to administrator without knowing the encryption key.