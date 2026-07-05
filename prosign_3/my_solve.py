import sys
import base64
import math
from Crypto.Util.number import *
from pwn import xor

def legendre_symbol(a, p):
	if pow(a, (p - 1) // 2, p) == 1: return True
	return False

def TS(a, p):
	if a % p == 0:
		return 0
	if not legendre_symbol(a, p):
		return None

	# 2. Trường hợp đặc biệt: p ≡ 3 (mod 4) giải rất nhanh
	if p % 4 == 3:
		return pow(a, (p + 1) // 4, p)

	# 3. Phân tích p - 1 = Q2^S -> TÌm đc Q và S

	S = 0
	Q = p - 1

	while Q % 2 == 0:
		S += 1
		Q //= 2

	# Tìm a quadratic non-residue z

	z = 2

	while legendre_symbol(z, p) != -1:
		z += 1

	c = pow(z, Q, p)

	R = pow(a, (Q + 1) // 2, p)

	t = pow(a, Q, p)

	M = S

	# Main loop
	#
	# Goal:
	# Make t become 1

	while t != 1:
		# Tìm i nhỏ nhất such that:
		# t^(2^i) ≡ 1 (mod p)
		
		i = 1
		temp = pow(t, 2, p)

		while temp != 1:
			temp = pow(temp, 2, p)
			i += 1
		b = pow(c, 2 ** (M - i - 1), p)
		
		R = (R * b) % p

		t = (t * b * b) % p

		c = (b * b) % p

		M = i
		
	return R

def egcd(a, b):
	if b == 0:
		return (a, 1, 0)

	g, x1, y1 = egcd(b, a % b)

	x = y1
	y = x1 - (a // b) * y1

	# print(x, y)

	return (g, x, y)

def inverse_mod(a, b):
	_, x, _ = egcd(a, b)
	return x % b

def add(p, q, a, b, m):
	if not p: return q
	if not q: return p

	x1, y1 = p[0], p[1]
	x2, y2 = q[0], q[1]
	lam = 0

	if x1 == x2 and y1 == (-y2) % m: return []
	if x1 == x2 and y1 == y2:
		lam = (((3 * x1 * x1 + a) % m) * inverse_mod(2 * y1, m)) % m 
	else: 
		lam = (((y2 - y1) % m) * inverse_mod(x2 - x1, m)) % m

	x3 = (lam * lam - x1 - x2) % m
	y3 = (lam * (-x3 + x1) - y1) % m 

	return [x3, y3]

def scalar_mul(n, P, a, b, m):
	Q = P
	R = []
	while n > 0:
		if n & 1:
			R = add(R, Q, a, b, m)
		n >>= 1
		Q = add(Q, Q, a, b, m)
	return R

def montgomery_ladder_ignore_y(k, x_G, p, A):
	x0, z0 = x_G, 1
	x1, z1 = xDBL(x0, z0, A, p)    
	bits = bin(k)[2:]
	for bit in bits[1:]:
		if bit == '0':
			x1, z1 = xADD(x0, z0, x1, z1, x_G, p)
			x0, z0 = xDBL(x0, z0, A, p)
		else:
			x0, z0 = xADD(x0, z0, x1, z1, x_G, p)
			x1, z1 = xDBL(x1, z1, A, p)

	return (x0 * pow(z0, -1, p)) % p

def xDBL(x, z, A, p):
	t0 = (x + z) % p
	t1 = (x - z) % p
	t0_sq = pow(t0, 2, p)
	t1_sq = pow(t1, 2, p)
	
	x2 = (t0_sq * t1_sq) % p
	
	a24 = (A + 2) * pow(4, -1, p) % p # Often denoted as (A+2)/4
	t2 = (t0_sq - t1_sq) % p
	z2 = (t2 * (t1_sq + a24 * t2)) % p
	
	return x2, z2

def xADD(x1, z1, x2, z2, x_diff, p):
	t0 = (x1 - z1) * (x2 + z2) % p
	t1 = (x1 + z1) * (x2 - z2) % p
	
	x_sum = pow(t0 + t1, 2, p)
	z_sum = (x_diff * pow(t0 - t1, 2, p)) % p
	
	return x_sum, z_sum

def affine_add(P, Q, A, B, p):
	x1, y1 = P
	x2, y2 = Q
	# Formula: alpha = (y2 - y1) / (x2 - x1)
	alpha = ((y2 - y1) * pow(x2 - x1, -1, p)) % p
	x3 = (B * pow(alpha, 2) - A - x1 - x2) % p
	y3 = (alpha * (x1 - x3) - y1) % p
	return (x3, y3)

def affine_dbl(P, A, B, p):
	x1, y1 = P
	# Formula: alpha = (3*x1^2 + 2*A*x1 + 1) / (2*B*y1)
	alpha = ((3 * pow(x1, 2) + 2 * A * x1 + 1) * pow(2 * B * y1, -1, p)) % p
	x3 = (B * pow(alpha, 2) - A - 2 * x1) % p
	y3 = (alpha * (x1 - x3) - y1) % p
	return (x3, y3)

def montgomery_ladder(k, G, A, B, p):
	"""
	Performs scalar multiplication [k]G using the affine Montgomery Ladder.
	G is a tuple (x, y).
	"""
	# 1. Initialize R0 = P, R1 = [2]P
	R0 = G
	R1 = affine_dbl(R0, A, B, p)
	
	# Get bit length of k
	bit_length = k.bit_length()
	
	# 2. Loop from bit_length - 2 down to 0
	# Note: We skip the first bit (n-1) because we initialized R0 and R1
	for i in range(bit_length - 2, -1, -1):
		bit = (k >> i) & 1
		if bit == 0:
			# R1 = R0 + R1, R0 = 2*R0
			R1 = affine_add(R0, R1, A, B, p)
			R0 = affine_dbl(R0, A, B, p)
		else:
			# R0 = R0 + R1, R1 = 2*R1
			R0 = affine_add(R0, R1, A, B, p)
			R1 = affine_dbl(R1, A, B, p)
			
	# 3. Return the x-coordinate of R0
	return R0[0]

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)

    g, x1, y1 = egcd(b, a % b)

    x = y1
    y = x1 - (a // b) * y1

    # print(x, y)

    return (g, x, y)

def crt(inp):
	M = 1
	for i in range(0, len(inp)): 
		M *= inp[i][1]

	ans = 0
	for i in range(0, len(inp)):
		p = inp[i][1]
		Mi = M // p
		_, yi, _ = egcd(min(Mi, Mi % p), p)
		yi %= p
		ans += inp[i][0] * yi * Mi

	return ans % M

def fact_analyze(n):
	f = []
	for i in range(2, int(math.sqrt(n)) + 1):
		if (n % i == 0):
			j = 1
			while (n % i == 0):
				n //= i 
				j *= i
			f.append(j)

	if (n != 1): f.append(n)

	return f 

def bsgs(G_sub, H_sub, order, a, b, p):
    """Baby-step Giant-step: find x such that x * G_sub == H_sub, 0 <= x < order"""
    m = math.isqrt(order) + 1
    
    # Baby step: compute j * G_sub for j = 0, 1, ..., m-1
    baby = {}
    temp = []  # point at infinity
    for j in range(m):
        # Use tuple as dict key (lists aren't hashable)
        key = tuple(temp) if temp else (0, 0, "inf")
        baby[key] = j
        temp = add(temp, G_sub, a, b, p)
    
    # Giant step factor: -m * G_sub
    neg_mG = scalar_mul(m, G_sub, a, b, p)
    # Negate: (x, y) -> (x, -y mod p)
    if neg_mG:
        neg_mG = [neg_mG[0], (-neg_mG[1]) % p]
    
    # Giant step: check H_sub + i * (-m * G_sub) for i = 0, 1, ...
    gamma = list(H_sub) if H_sub else []
    for i in range(m):
        key = tuple(gamma) if gamma else (0, 0, "inf")
        if key in baby:
            return (i * m + baby[key]) % order
        gamma = add(gamma, neg_mG, a, b, p)
    
    return None  


def polig_hellmen_for_ECC(order, G, H, a, b, p, fact):
    n = order
    inp = []
    for i in range(len(fact)):
        m = n // fact[i]
        # Project POINTS to subgroup via scalar multiplication
        G_sub = scalar_mul(m, G, a, b, p)
        H_sub = scalar_mul(m, H, a, b, p)
        
        x = bsgs(G_sub, H_sub, fact[i], a, b, p)

        inp.append([x, fact[i]])
    
    return crt(inp)


p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
order = 115792089210356248762697446949407573529996955224135760342422259061068512044369
G = [0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296, 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5]
H = [0x3B827FF5E8EA151E6E51F8D0ABF08D90F571914A595891F9998A5BD49DFA3531, 0xAB61705C502CA0F7AA127DEC096B2BBDC9BD3B4281808B3740C320810888592A]
a = -3
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
fact = [2, 3, 5**2, 17, 257, 641, 1531, 65537, 490463, 6700417, 835945042244614951780389953367877943453916927241] 
# print(polig_hellmen_for_ECC(order, G, H, a, b, p, fact))
print(scalar_mul(inverse_mod(2, order), H, a, b, p))
# print(scalar_mul(203194937053061868556704865251970439522, [272640099140026426377756188075937988094, 51062462309521034358726608268084433317], 2, 3, p))
# 203194937053061868556704865251970439522