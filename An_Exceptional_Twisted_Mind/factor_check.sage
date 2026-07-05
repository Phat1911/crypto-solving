p = 13407807929942597099574024998205846127479365820592393377723561443721764030029777567070168776296793595356747829017949996650141749605031603191442486002224009
a = -3
b = 152961

E = EllipticCurve(GF(p), [a, b])
N = E.order()
N_twist = 2*(p+1) - N

print("[*] Factoring E.order() using trial division and ECM...")
# Try factoring using trial division and ECM for 5 seconds
# if it has smooth parts, ECM will find them instantly.
try:
    print("N factors:", N.factor(limit=10**8))
except Exception as e:
    print("N factor error:", e)

try:
    print("N_twist factors:", N_twist.factor(limit=10**8))
except Exception as e:
    print("N_twist factor error:", e)
