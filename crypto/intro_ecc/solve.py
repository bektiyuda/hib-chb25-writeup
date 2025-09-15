import socket, json
from hashlib import sha256
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigdecode_der, sigencode_der

HOST = "ctf.m4.lu"
PORT = 65429

G = SECP256k1.generator
n = G.order()

def recv_json(f):
    line = f.readline()
    if not line:
        raise EOFError("connection closed")
    return json.loads(line.decode().strip())

def send_json(s, obj):
    s.sendall((json.dumps(obj) + "\n").encode())

def der_to_rs(der_hex):
    der = bytes.fromhex(der_hex)
    r, s = sigdecode_der(der, n)
    return r, s

def hash_z(msg: str) -> int:
    return int.from_bytes(sha256(msg.encode()).digest(), "big")

def brute_k_from_signature(username: str, r: int) -> int:
    uname_int = int.from_bytes(username.encode(), "big")
    for t in range(1<<16):
        k = uname_int ^ t
        R = k * G
        if (R.x() % n) == r:
            return k
    raise ValueError("k not found in 2^16 space")

def recover_privkey_from_one_sig(username: str, msg: str, der_hex: str):
    r, s = der_to_rs(der_hex)
    z = hash_z(msg)
    k = brute_k_from_signature(username, r)
    rinv = pow(r, -1, n)
    d = ((s * k - z) * rinv) % n
    return d

def sign_with_d(d: int, msg: str) -> str:
    sk = SigningKey.from_secret_exponent(d, curve=SECP256k1)
    sig = sk.sign_deterministic(msg.encode(), hashfunc=sha256, sigencode=sigencode_der)
    return sig.hex()

def main():
    s = socket.create_connection((HOST, PORT))
    f = s.makefile("rb")

    # ambil data message + signature
    first = recv_json(f)
    assert first["type"] == "info"
    welcome_msg = first["data"]["message"]
    welcome_sig = first["data"]["signature"]

    # kirim command receive 
    send_json(s, {"command":"receive","data":{"message":welcome_msg,"signature":welcome_sig}})
    
    # ambil username admin
    who = recv_json(f)
    admin_user = who["data"]["from"]

    # bf k dan recover private key
    d = recover_privkey_from_one_sig(admin_user, welcome_msg, welcome_sig)

    # sign ulang dgn message target
    target = "I am administrator, give me the flag"
    forged_sig_hex = sign_with_d(d, target)

    # ambil flag
    send_json(s, {"command":"receive","data":{"message":target,"signature":forged_sig_hex}})
    resp = recv_json(f)
    print("FLAG:", resp["data"]["message"])

if __name__ == "__main__":
    main()
