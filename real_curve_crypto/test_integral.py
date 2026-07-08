from mpmath import mp
import random

mp.dps = 200

def lift_x(x):
    return mp.sqrt(x**3 - x)

def double(pt):
    x, y = pt
    m = (3*x*x - 1)/(2 * y)
    xf = m*m - 2*x
    yf = -(y + m*(xf - x))
    return (xf, yf)

def add(pt1, pt2):
    x1, y1 = pt1
    x2, y2 = pt2
    m = (y1 - y2)/(x1 - x2)
    xf = m*m - x1 - x2
    yf = -(y1 + m*(xf - x1))
    return (xf, yf)

def scalar_multiply(pt, m):
    if m == 1:
        return pt
    half_mult = scalar_multiply(pt, m // 2)
    ans = double(half_mult)
    if m % 2 == 1:
        ans = add(ans, pt)
    return ans

def unroll(x, y):
    # Integral from x to infinity of 1/sqrt(t^3 - t)
    integral = mp.quad(lambda t: 1/mp.sqrt(t**3 - t), [x, mp.inf])
    if y < 0:
        return -integral
    return integral

gx = mp.mpf(1.5)
gy = lift_x(gx)
G = (gx, gy)

N = random.getrandbits(128)
P = scalar_multiply(G, N)

dist_G = unroll(G[0], G[1])
dist_P = unroll(P[0], P[1])
period = 2 * mp.quad(lambda t: 1/mp.sqrt(t**3 - t), [1, mp.inf])

print("Distance G:", dist_G)
print("Distance P:", dist_P)
print("Period:", period)
print("True N:", N)

# We want N * dist_G = dist_P + k * period
# Divide by period:
# N * (dist_G / period) - k = (dist_P / period)
# So N * (dist_G / period) \equiv (dist_P / period)  (mod 1)
