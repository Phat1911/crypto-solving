from collections import namedtuple
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import inverse
from hashlib import sha256
import os

p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b_val = 1

E = EllipticCurve(GF(p), [-3, b_val])
N = E.order()
prime = 1229

while True:
    G = E.random_element()
    Q_m = (N // prime) * G
    if Q_m != E(0):
        break

Point = namedtuple("Point", "x y")
Curve = namedtuple("Curve", "p a b G")
O = "Origin"

def point_inverse(P, C):
    if P == O:
        return P
    return Point(P.x, -P.y % C.p)

def point_addition(P, Q, C):
    if P == O:
        return Q
    elif Q == O:
        return P
    elif Q == point_inverse(P, C):
        return O
    else:
        if P == Q:
            lam = (3 * P.x**2 + C.a) * inverse(2 * P.y, C.p)
            lam %= C.p
        else:
            lam = (Q.y - P.y) * inverse((Q.x - P.x), C.p)
            lam %= p
    Rx = (lam**2 - P.x - Q.x) % C.p
    Ry = (lam * (P.x - Rx) - P.y) % C.p
    R = Point(Rx, Ry)
    return R

def double_and_add(P, n, C):
    Q = P
    R = O
    while n > 0:
        if n % 2 == 1:
            R = point_addition(R, Q, C)
        Q = point_addition(Q, Q, C)
        n = n // 2
    return R

s_mock = 838
C = Curve(p, a, b_val, Point(int(Q_m[0]), int(Q_m[1])))

shared_point = double_and_add(C.G, s_mock, C)
shared_key = sha256(str(shared_point.x).encode()).digest()[:16]

iv = os.urandom(16)
cipher = AES.new(shared_key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(b"SERVER_TEST_MESSAGE", 16))

# Let's print string representations
str1 = str(shared_point.x)
sage_point = s_mock * Q_m
str2 = str(int(sage_point[0]))

print("str1:", str1[:20] + "..." if len(str1) > 20 else str1)
print("str2:", str2[:20] + "..." if len(str2) > 20 else str2)
print("Strings equal:", str1 == str2)

key_correct = sha256(str2.encode()).digest()[:16]
print("Keys equal:", shared_key == key_correct)

cipher_dec = AES.new(key_correct, AES.MODE_CBC, iv)
decrypted = cipher_dec.decrypt(ciphertext) # Decrypt the entire ciphertext!
print("Fully decrypted:", decrypted)
