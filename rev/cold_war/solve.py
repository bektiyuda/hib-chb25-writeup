# target compute_b(launch_code) == (wrong() ^ xor)
def wrong() -> bytes:
    return bytes([167, 191, 210, 158, 15, 1, 107, 83, 104, 55, 183, 96, 124, 186, 180, 168])

xor = [212, 162, 242, 218, 101, 109, 50, 31, 125, 112, 249, 83, 55, 187, 131, 206]

rows = [
    [2,3,4,8,11,14],
    [0,1,8,11,13,14],
    [0,1,2,4,5,8,9,10,13,14,15],
    [5,6,8,9,10,12,15],
    [1,6,7,8,12,13,14,15],
    [0,4,7,8,9,10,12,13,14,15],
    [1,3,7,9,10,11,12,13,15],
    [0,1,2,3,4,8,10,11,14],
    [1,2,3,5,9,10,11,12],
    [6,7,8,10,11,12,15],
    [0,3,4,7,8,10,11,12,13,14,15],
    [0,2,4,6,13],
    [0,3,6,7,10,12,15],
    [2,3,4,5,6,7,11,12,13,14],
    [1,2,3,5,7,11,13,14,15],
    [1,3,5,9,10,11,13,15],
]
A = [[0]*16 for _ in range(16)]
for i, cols in enumerate(rows):
    for c in cols: A[i][c] ^= 1
h = [a ^ b for a, b in zip(list(wrong()), xor)]  # target

# eliminasi Gauss di XOR (GF(2))
B = [row[:] for row in A]
rhs = h[:]
piv = [-1]*16
r = 0
for c in range(16):
    p = next((i for i in range(r,16) if B[i][c]), None)
    if p is None: continue
    if p != r:
        B[r], B[p] = B[p], B[r]
        rhs[r], rhs[p] = rhs[p], rhs[r]
    piv[r] = c
    for i in range(16):
        if i != r and B[i][c]:
            B[i] = [x ^ y for x, y in zip(B[i], B[r])]
            rhs[i] ^= rhs[r]
    r += 1

x = [0]*16
col2row = {piv[row]: row for row in range(16) if piv[row] != -1}
for col in range(15, -1, -1):
    if col not in col2row: continue
    row = col2row[col]
    val = rhs[row]
    for j in range(col+1, 16):
        if B[row][j]: val ^= x[j]
    x[col] = val

launch_code = bytes(x)
print(launch_code)