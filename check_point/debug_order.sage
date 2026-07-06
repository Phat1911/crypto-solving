p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
prime, b_val = 1229, 1
E = EllipticCurve(GF(p), [-3, b_val])
N = E.order()

print("N divisible by 1229:", N % 1229 == 0)

while True:
    G = E.random_element()
    Q_m = (N // prime) * G
    if Q_m != E(0):
        break

print("Q_m order:", Q_m.order())
print("Q_m lies on E:", Q_m in E)
