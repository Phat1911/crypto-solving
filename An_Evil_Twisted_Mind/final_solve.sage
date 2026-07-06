import socket
import json
import time
from sage.all import *

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("socket.cryptohack.org", 13418))
    return s

modulus = 22940775619019322596732579295592937688786860238433707977002010287174316620572298541233055185492572749161011953122651
a = -3
b = 2697448053935541741976221051345108825177671050689533270507
order_limit = 4782850957738000717885060297297408935631027604045525430677

p1 = 4782850957738000717885060297350722702854694354378697989111
p2 = 4796464665474109238546017500238174976861701183900526078141

F1 = GF(p1)
D1 = F1(2)
while D1.is_square(): D1 += 1
E_twist1 = EllipticCurve(F1, [a*D1**2, b*D1**3])

F2 = GF(p2)
D2 = F2(2)
while D2.is_square(): D2 += 1
E_twist2 = EllipticCurve(F2, [a*D2**2, b*D2**3])

twist_order1 = 4782850957738000717885060297404036470078361104711870547547
twist_order2 = 4796464665474109238546017500227485109621464114066943970077

q_1 = [1965293129, 3945014767, 6911909839]
q_2 = [17, 1789, 8984179, 9381319, 83816652113]

Q1 = prod(q_1)
Q2 = prod(q_2)

def generate_P1():
    while True:
        P = E_twist1.random_point()
        P_tot = E_twist1(0)
        for q in q_1:
            P_q = (twist_order1 // q) * P
            if P_q != E_twist1(0):
                P_tot += P_q
        if P_tot != E_twist1(0):
            return P_tot

def generate_P2():
    while True:
        P = E_twist2.random_point()
        P_tot = E_twist2(0)
        for q in q_2:
            P_q = (twist_order2 // q) * P
            if P_q != E_twist2(0):
                P_tot += P_q
        if P_tot != E_twist2(0):
            return P_tot

print("[+] Generating points...")
P_total1 = generate_P1()
P_total2 = generate_P2()

x1 = int(P_total1[0] / D1)
x2 = int(P_total2[0] / D2)
x0 = crt([x1, x2], [p1, p2])

s = connect()
print(s.recv(1024).decode())

print(f"[+] Sending x0...")
s.sendall(json.dumps({"option": "get_pubkey", "x0": str(x0)}).encode() + b"\n")
resp = json.loads(s.recv(1024).decode().strip())
X_out = int(resp["pubkey"])
print(f"[+] Received X_out")

print("[+] Solving DLP 1...")
X_Q1 = F1(X_out) * D1
Y_Q1 = (X_Q1**3 + a*D1**2*X_Q1 + b*D1**3).sqrt()
Q_total1 = E_twist1(X_Q1, Y_Q1)

rems1 = []
for q in q_1:
    base = (twist_order1 // q) * P_total1
    target = (twist_order1 // q) * Q_total1
    rem = discrete_log(target, base, ord=q, operation='+')
    rems1.append(rem)
d1 = crt(rems1, q_1)

print("[+] Solving DLP 2...")
X_Q2 = F2(X_out) * D2
Y_Q2 = (X_Q2**3 + a*D2**2*X_Q2 + b*D2**3).sqrt()
Q_total2 = E_twist2(X_Q2, Y_Q2)

rems2 = []
for q in q_2:
    base = (twist_order2 // q) * P_total2
    target = (twist_order2 // q) * Q_total2
    rem = discrete_log(target, base, ord=q, operation='+')
    rems2.append(rem)
d2 = crt(rems2, q_2)

print("[+] Generating candidates...")
M = Q1 * Q2
cands_to_try = []
for c1 in [d1, (-d1) % Q1]:
    for c2 in [d2, (-d2) % Q2]:
        P_0 = crt([c1, c2], [Q1, Q2])
        for k in range(215):
            cand = P_0 + k * M
            if cand <= order_limit // 2:
                cand_real = cand
            else:
                cand_real = (order_limit - cand) % order_limit
            cands_to_try.append(int(cand_real))

print(f"[+] Submitting {len(cands_to_try)} candidates...")
for c in cands_to_try:
    s.sendall(json.dumps({"option": "get_flag", "privkey": c}).encode() + b"\n")
    data = s.recv(1024).decode()
    if "crypto{" in data:
        print("[+] FLAG FOUND!")
        print(data)
        break

s.close()
