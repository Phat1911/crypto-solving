p1 = 4782850957738000717885060297350722702854694354378697989111
p2 = 4796464665474109238546017500238174976861701183900526078141
a = -3
b = 2697448053935541741976221051345108825177671050689533270507

E1 = EllipticCurve(GF(p1), [a, b])
E2 = EllipticCurve(GF(p2), [a, b])

twist_order1 = 2*p1 + 2 - E1.order()
twist_order2 = 2*p2 + 2 - E2.order()

print("Factoring twist 1...")
factors1 = factor(twist_order1)
print(factors1)

print("Factoring twist 2...")
factors2 = factor(twist_order2)
print(factors2)
