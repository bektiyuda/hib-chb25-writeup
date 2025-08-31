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
