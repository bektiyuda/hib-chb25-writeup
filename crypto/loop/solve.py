from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long

SALT_FMT = "_SALTED_{:02d}"

# Load public key
with open('out/public_key.pem', 'rb') as f:
    key = RSA.import_key(f.read())
n, e = key.n, key.e
modulus_size = (n.bit_length() + 7) // 8

# Load ciphertext
with open('out/encrypted_flag.bin', 'rb') as f:
    data = f.read()
blocks = [data[i:i+modulus_size] for i in range(0, len(data), modulus_size)]

PRINTABLE = [chr(i) for i in range(32, 127)]
flag_chars = []

for idx, block in enumerate(blocks):
    c_int = bytes_to_long(block)
    salt = SALT_FMT.format(idx+1)
    found = None
    # Coba semua printable ASCII
    for ch in PRINTABLE:
        m_int = bytes_to_long((ch + salt).encode())
        if pow(m_int, e, n) == c_int:
            found = ch
            break
    # Coba semua byte jika belum ketemu
    if found is None:
        for b in range(256):
            m_int = bytes_to_long(bytes([b]) + salt.encode())
            if pow(m_int, e, n) == c_int:
                found = bytes([b]).decode('latin1')
                break
    flag_chars.append(found if found else '?')

flag = ''.join(flag_chars)
print("Recovered flag:", flag)