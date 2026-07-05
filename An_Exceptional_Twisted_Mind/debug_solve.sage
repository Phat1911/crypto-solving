p = 115792089237316195423570985008687907853269984665640564039457584007913129639747
a = -3
b = 152961
order = 115792089237316195423570985008687907853233080465625507841270369819257950283813

R = IntegerModRing(p^2)
E_p2 = EllipticCurve(R, [a, b])
E_p = EllipticCurve(GF(p), [a, b])
N_p = E_p.order()

def lift_sqrt(y_sqr, p):
    y_sqr_p = GF(p)(y_sqr)
    y0 = int(y_sqr_p.sqrt())
    diff = int(y_sqr) - y0^2
    k = (diff // p) * inverse_mod(2 * y0, p) % p
    return y0 + k * p

# Simulating the attack
privkey = 123456789
while True:
    x_val = R.random_element()
    y_sqr = x_val^3 + a*x_val + b
    if GF(p)(y_sqr).is_square():
        y_val = lift_sqrt(y_sqr, p)
        P = E_p2(x_val, y_val)
        break

Q = privkey * P

# Define Qp curve using standard a, b parameters directly!
Eqp = EllipticCurve(Qp(p, 2), [a, b])

# Instantiate points directly
G_Qp = Eqp(ZZ(P[0]), ZZ(P[1]))
Pub_Qp = Eqp(ZZ(Q[0]), ZZ(Q[1]))

P0 = N_p * G_Qp
Pub0 = N_p * Pub_Qp

x1, y1 = P0.xy()
x2, y2 = Pub0.xy()

phi_G = -(x1 / y1)
phi_Pub = -(x2 / y2)

res = phi_Pub / phi_G
d = ZZ(res) % p
print("Candidate d:", d)
print("Is correct:", d == privkey or (order - d) % order == privkey)
