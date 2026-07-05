from Crypto.Util.number import long_to_bytes

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = -3
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b

E = EllipticCurve(GF(p), [a, b])

# NIST P-256 generator point coordinates and order
gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
G = E(gx, gy)
q = G.order()

# Given Private Key d and Hidden Flag Point T
d = 110104254168941847244659959021870001852301044662581657616531508669991620749093
hidden_flag_x = 16807196250009982482930925323199249441776811719221084165690521045921016398804
hidden_flag_y = 72892323560996016030675756815328265928288098939353836408589138718802282948311

T = E(hidden_flag_x, hidden_flag_y)

# Reverse the scalar multiplication: Q = d^-1 * T
d_inv = inverse_mod(d, q)
Q = d_inv * T

# Decode the x-coordinate of point Q into the flag bytes
flag = long_to_bytes(int(Q[0]))
print(flag.decode('utf-8'))
