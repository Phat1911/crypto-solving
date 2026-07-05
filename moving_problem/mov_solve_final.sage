from sage.all import *
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# 1. Setup the Curve
p = 1331169830894825846283645180581
a = -35
b = 98

E = EllipticCurve(GF(p), [a, b])
N = E.order()

P = E(479691812266187139164535778017, 568535594075310466177352868412) # Generator Point G
Q = E(1110072782478160369250829345256, 800079550745409318906383650948) # Alice's Public Key
Bob_P = E(1290982289093010194550717223760, 762857612860564354370535420319) # Bob's Public Key

# 2. Find Embedding Degree 'k'
k = 1
while (p**k - 1) % N != 0:
    k += 1

print(f"[*] Found Embedding Degree: k = {k}")

# 3. Extend the Field (if k > 1)
if k == 1:
    E_ext = E
    P_ext = P
    Q_ext = Q
else:
    print(f"[*] Extending the Finite Field to GF(p^{k})...")
    F_ext = GF(p**k, name='u')
    u = F_ext.gen()
    E_ext = EllipticCurve(F_ext, [a, b])
    P_ext = E_ext(P)
    Q_ext = E_ext(Q)

# 4. Find independent point R
print("[*] Finding an independent random point R for the scanner...")

# To avoid SageMath freezing on E_ext.order(), we use Algebraic Geometry to find the exact cofactor!
cofactor = 2 * p + 2 - N

# Instead of using the black-box .random_point() which might hang, 
# we can pick the point DIRECTLY by guessing an X coordinate in the extension field!
x_val = u # 'u' is the generator of our GF(p^2) extension field
while True:
    # 1. Plug X into the curve equation: x^3 + ax + b
    rhs = x_val**3 + a*x_val + b
    
    # 2. Check if the result is a perfect square
    if rhs.is_square():
        # 3. Take the square root to get Y
        y_val = sqrt(rhs)
        
        # 4. We found our direct point!
        R_base = E_ext(x_val, y_val)
        
        # 5. Multiply by the cofactor to ensure its order is exactly N
        R = cofactor * R_base
        
        if R != E_ext(0) and P_ext.weil_pairing(R, N) != 1:
            break
            
    # If not a square, try the next X coordinate
    x_val += 1

print("[*] Point R found! Cross-scanning points with Weil Pairing...")

# 5. Calculate Pairings
u = P_ext.weil_pairing(R, N)
v = Q_ext.weil_pairing(R, N)

# 6. Solve Discrete Log
print("[*] Solving Discrete Logarithm (v = u^d) in the Finite Field...")
# We MUST explicitly pass `ord=N` to SageMath! 
# If we don't, SageMath tries to factor the massive (p^2 - 1) to find the order, which takes forever.
# With ord=N, SageMath will instantly factor N and use Pohlig-Hellman!
d = discrete_log(v, u, ord=N)
print(f"[+] Private Key 'd': {d}")

# 7. Decrypt the Flag
print("[*] Decrypting AES Flag...")
# Generate Shared Secret S = d * Bob_P
S = d * Bob_P
shared_x = str(S.xy()[0]).encode('ascii')

# Hash shared secret to get AES key
sha1 = hashlib.sha1()
sha1.update(shared_x)
key = sha1.digest()[:16]

# AES Decryption
iv = bytes.fromhex('eac58c26203c04f68d63dc2c58d79aca')
encrypted_flag = bytes.fromhex('bb9ecbd3662d0671fd222ccb07e27b5500f304e3621a6f8e9c815bc8e4e6ee6ebc718ce9ca115cb4e41acb90dbcabb0d')

cipher = AES.new(key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(encrypted_flag), 16).decode()
print(f"[+] FLAG: {flag}")
