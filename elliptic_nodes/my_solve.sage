from sage.all import *
from Crypto.Util.number import long_to_bytes

# The given curve parameters from the challenge
p = 4368590184733545720227961182704359358435747188309319510520316493183539079703

# Generator point G
gx = 8742397231329873984594235438374590234800923467289367269837473862487362482
gy = 225987949353410341392975247044711665782695329311463646299187580326445253608

# Public key point Q
qx = 2582928974243465355371953056699793745022552378548418288211138499777818633265
qy = 2421683573446497972507172385881793260176370025964652384676141384239699096612

print("[*] Starting Singular Curve Attack...")

# Step 1: Recover hidden parameters 'a' and 'b' by solving the system of equations
# gy^2 = gx^3 + a*gx + b
# qy^2 = qx^3 + a*qx + b
inv_diff = inverse_mod(gx - qx, p)
a = ((gy**2 - gx**3) - (qy**2 - qx**3)) * inv_diff % p
b = (gy**2 - gx**3 - a*gx) % p

print(f"[*] Recovered a = {a}")
print(f"[*] Recovered b = {b}")

# Step 2: Find the double root (the Node) of the polynomial x^3 + a*x + b
F = GF(p)
R = PolynomialRing(F, 'x')
x = R.gen()
f = x**3 + a*x + b
roots = f.roots()

# Locate the root with multiplicity >= 2
r = None
for root, multiplicity in roots:
    if multiplicity >= 2:
        r = root
        break

print(f"[*] Found the node (double root) at x = {r}")

# Step 3: Calculate the constant 'c' for the shifted curve (Y^2 = X^3 + c*X^2)
c = 3 * r
sqrt_c = mod(c, p).sqrt()

# Step 4: Define the mapping function to the multiplicative group
def map_to_field(px, py):
    # Shift the point so the node is at (0,0) and cast to GF(p)
    X = F(px - r)
    Y = F(py)
    
    # Calculate ratio of the two tangent lines
    # Because X and Y are in GF(p), we can just use normal division!
    mapped_val = (Y + X * sqrt_c) / (Y - X * sqrt_c)
    return mapped_val

u = map_to_field(gx, gy)
v = map_to_field(qx, qy)

print(f"[*] Mapped G to u = {u}")
print(f"[*] Mapped Q to v = {v}")

# Step 5: Solve the Discrete Logarithm (u^d = v mod p)
print("[*] Solving the discrete logarithm using SageMath's built-in Pohlig-Hellman...")
d = discrete_log(F(v), F(u))

print(f"[+] Recovered Private Key (d) = {d}")
print(f"[+] FLAG: {long_to_bytes(d).decode('utf-8')}")
