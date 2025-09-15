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

username = "testwuhib"
token    = "iMhIpPcf3LiSsy-rsjvzE11LdxIxZcLzOVEAmd98lzYrpglDd9WDDuyObmUt-jRWUgpnMW1oqmTOeP26b3c6tg=="

admin_token = forge_token(token, username, "admin")
print("New auth_token:")
print(admin_token)