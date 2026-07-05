from sage.all import *

print("=== STEP 1: Setting up a small anomalous curve ===")
# We will find a tiny anomalous curve (where modulus p == curve order)
p = 11
found = False
for a in range(p):
    for b in range(p):
        try:
            E = EllipticCurve(GF(p), [a, b])
            if E.order() == p:
                found = True
                break
        except:
            pass
    if found:
        break

print(f"Curve E: y^2 = x^3 + {a}x + {b} over GF({p})")
print(f"Modulus (p): {p}")
print(f"Number of points (Order): {E.order()}")
print(f"Is it anomalous? {E.order() == p}\n")

print("=== STEP 2: Creating a Public Key ===")
G = E.gens()[0]
private_key = 7  # Our secret multiplier
Pub = private_key * G
print(f"Generator G: {G.xy()}")
print(f"Alice's secret private key: {private_key}")
print(f"Public Key (Pub = {private_key} * G): {Pub.xy()}\n")

print("=== STEP 3: Smart's Attack - Lifting to p-adics ===")
Eqp = EllipticCurve(Qp(p, 2), [ZZ(a), ZZ(b)])
print(f"Created new p-adic curve Eqp over Qp({p}, 2)")

# Lift G
G_Qp = Eqp.lift_x(ZZ(G.xy()[0]), all=True)[0]
if GF(p)(G_Qp.xy()[1]) != G.xy()[1]:
    G_Qp = -G_Qp

# Lift Pub
Pub_Qp = Eqp.lift_x(ZZ(Pub.xy()[0]), all=True)[0]
if GF(p)(Pub_Qp.xy()[1]) != Pub.xy()[1]:
    Pub_Qp = -Pub_Qp
print(f"Lifted both points into the p-adic universe.\n")

print("=== STEP 4: Multiplying by p ===")
p_G = p * G_Qp
p_Pub = p * Pub_Qp
print("By multiplying by p (which is 11), the points get 'pushed' very close to zero.")
x1, y1 = p_G.xy()
x2, y2 = p_Pub.xy()
print(f"Look at the X and Y coordinates of (p * G). Notice they are multiples of 11 (O(11^something))!")
print(f"  X: {x1}")
print(f"  Y: {y1}\n")

print("=== STEP 5: The p-adic logarithm ===")
print("We compute the 'logarithm' by calculating: -(x / y)")
phi_G = -(x1 / y1)
phi_Pub = -(x2 / y2)
print(f"Logarithm of G:   {phi_G}")
print(f"Logarithm of Pub: {phi_Pub}\n")

print("=== STEP 6: Extracting the Private Key ===")
print("Because the logarithms are linear, we just divide them to get the private key!")
print(f"Calculation: ({phi_Pub}) / ({phi_G})")
recovered_key = ZZ(phi_Pub / phi_G) % p
print(f"Recovered Private Key: {recovered_key}")

if recovered_key == private_key:
    print("\n[+] SUCCESS! The math works perfectly.")
