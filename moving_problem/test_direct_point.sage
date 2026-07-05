from sage.all import *

p = 1331169830894825846283645180581
a = -35
b = 98

E = EllipticCurve(GF(p), [a, b])
N = E.order()
k = 2

F_ext.<u> = GF(p**k)
E_ext = EllipticCurve(F_ext, [a, b])

cofactor = 2 * p + 2 - N

# Try to find a point directly
x_val = u
while True:
    rhs = x_val**3 + a*x_val + b
    if rhs.is_square():
        y_val = sqrt(rhs)
        R_base = E_ext(x_val, y_val)
        break
    x_val += 1

print(f"Base R found: {R_base}")
R = cofactor * R_base
print(f"Final R: {R}")
