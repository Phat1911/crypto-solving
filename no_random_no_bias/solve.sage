from hashlib import sha1
from Crypto.Util.number import bytes_to_long

# --- NIST P-256 Curve Parameters ---
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = -3
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

E = EllipticCurve(GF(p), [a, b])

# P-256 Base point G
gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
G = E(gx, gy)
q = G.order()

# --- Public data from output file ---
pubkey_x = 48780765048182146279105449292746800142985733726316629478905429239240156048277
pubkey_y = 74172919609718191102228451394074168154654001177799772446328904575002795731796

sigs = [
    {
        'msg': 'I have hidden the secret flag as a point of an elliptic curve using my private key.',
        'r': 0x91f66ac7557233b41b3044ab9daf0ad891a8ffcaf99820c3cd8a44fc709ed3ae,
        's': 0x1dd0a378454692eb4ad68c86732404af3e73c6bf23a8ecc5449500fcab05208d
    },
    {
        'msg': 'The discrete logarithm problem is very hard to solve, so it will remain a secret forever.',
        'r': 0xe8875e56b79956d446d24f06604b7705905edac466d5469f815547dea7a3171c,
        's': 0x582ecf967e0e3acf5e3853dbe65a84ba59c3ec8a43951bcff08c64cb614023f8
    },
    {
        'msg': 'Good luck!',
        'r': 0x566ce1db407edae4f32a20defc381f7efb63f712493c3106cf8e85f464351ca6,
        's': 0x9e4304a36d2c83ef94e19a60fb98f659fa874bfb999712ceb58382e2ccda26ba
    }
]

# --- Prepare HNP parameters ---
t = []
u = []

for sig in sigs:
    hsh = sha1(sig['msg'].encode()).digest()
    z = bytes_to_long(hsh)
    s_inv = inverse_mod(sig['s'], q)
    t_val = (s_inv * sig['r']) % q
    u_val = (s_inv * z) % q
    t.append(t_val)
    u.append(u_val)

# --- Lattice Setup ---
shift = 2**96
Q = shift * q

matrix_data = [
    [ Q, 0, 0, 0, 0 ],
    [ 0, Q, 0, 0, 0 ],
    [ 0, 0, Q, 0, 0 ],
    [ shift * t[0], shift * t[1], shift * t[2], 1, 0 ],
    [ -shift * u[0], -shift * u[1], -shift * u[2], 0, 2**256 ]
]

L = Matrix(ZZ, matrix_data)
L_reduced = L.LLL()

print("[*] Running LLL basis reduction...")

# Find private key d
d = None
pubkey_point = E(pubkey_x, pubkey_y)

for row in L_reduced:
    candidate = int(row[3])
    if candidate < 0:
        candidate = -candidate
    candidate = candidate % q
    
    if candidate != 0:
        if candidate * G == pubkey_point:
            d = candidate
            break
        if (q - candidate) * G == pubkey_point:
            d = q - candidate
            break

if d is not None:
    print(f"[+] Private key found: {d}")
else:
    print("[-] Private key not found.")
