import socket
import json
import sys
import os
import operator
from sage.all import *

sys.stdout.reconfigure(line_buffering=True)

# Parameters
modulus = 22940775619019322596732579295592937688786860238433707977002010287174316620572298541233055185492572749161011953122651
a = -3
b = 2697448053935541741976221051345108825177671050689533270507
order_limit = 4782850957738000717885060297297408935631027604045525430677

# Hardcode the known values to save time!
x0 = 20371432088048885906403069623744095520244882160477924944143601189070776773367857995054508873385598768779007383003841
X_out = 14194537083459276024558858301674843866981827347649041461710836077384998998445224767713863738990023789586227518500697

p1 = 4782850957738000717885060297350722702854694354378697989111
p2 = 4796464665474109238546017500238174976861701183900526078141

q_1 = [1965293129, 3945014767, 6911909839]
q_2 = [17, 1789, 8984179, 9381319, 83816652113]

remainders_1 = [715638879, 3509980814, 1910311671]
remainders_2 = [3, 1422, 5696365, 2483279, 29337851095]

Q1 = prod(q_1)
Q2 = prod(q_2)
d1 = crt(remainders_1, q_1)
d2 = crt(remainders_2, q_2)

combos1 = [d1, (-d1) % Q1]
combos2 = [d2, (-d2) % Q2]

Q_total = Q1 * Q2
base_cands = []
for c1 in combos1:
    for c2 in combos2:
        d_crt = crt([c1, c2], [Q1, Q2])
        base_cands.append(int(d_crt))

base_cands = list(set(base_cands))

def server_scalarmult_int(scalar, x0_val, mod):
    scalar = int(scalar)
    x0_val = int(x0_val)
    mod = int(mod)
    
    def dbl_int(P1):
        X1, Z1 = P1
        XX = X1**2 % mod
        ZZ = Z1**2 % mod
        A = 2 * ((X1 + Z1) ** 2 - XX - ZZ) % mod
        aZZ = int(a) * ZZ % mod
        X3 = ((XX - aZZ) ** 2 - 2 * int(b) * A * ZZ) % mod
        Z3 = (A * (XX + aZZ) + 4 * int(b) * ZZ**2) % mod
        return (X3, Z3)
        
    def diffadd_int(P1, P2):
        X1, Z1 = P1
        X2, Z2 = P2
        X1Z2 = X1 * Z2 % mod
        X2Z1 = X2 * Z1 % mod
        Z1Z2 = Z1 * Z2 % mod
        T = (X1Z2 + X2Z1) * (X1 * X2 + int(a) * Z1Z2) % mod
        Z3 = (X1Z2 - X2Z1) ** 2 % mod
        X3 = (2 * T + 4 * int(b) * Z1Z2**2 - x0_val * Z3) % mod
        return (X3, Z3)
        
    R0 = (x0_val, 1)
    R1 = dbl_int(R0)
    n = scalar.bit_length()
    pbit = 0
    for i in range(n - 2, -1, -1):
        bit = (scalar >> i) & 1
        pbit = pbit ^^ bit
        if pbit:
            R0, R1 = R1, R0
        R1 = diffadd_int(R0, R1)
        R0 = dbl_int(R0)
        pbit = bit
    if bit:
        R0 = R1
    return (R0[0] * inverse_mod(R0[1], mod)) % mod

found_privkey = None

for base_cand in base_cands:
    cand_real = min(base_cand % order_limit, (order_limit - base_cand) % order_limit)
    test_out = server_scalarmult_int(cand_real, x0, modulus)
    if test_out == X_out:
        print(f"    [+] MATCH! Found Privkey: {cand_real}")
        found_privkey = cand_real
        break

if found_privkey is not None:
    print(f"\n[+] Sending privkey to server: {found_privkey}")
    
    s = socket.socket()
    s.connect(("socket.cryptohack.org", 13418))
    buffer = b""

    def read_until(string):
        global buffer
        while string.encode() not in buffer:
            chunk = s.recv(1024)
            if not chunk: break
            buffer += chunk
        parts = buffer.split(string.encode(), 1)
        res = parts[0]
        buffer = parts[1]
        return res

    read_until("in decimal format.\n")
    s.sendall(json.dumps({"option": "get_flag", "privkey": int(found_privkey)}).encode() + b"\n")
    resp = json.loads(read_until("\n").decode())
    
    if "flag" in resp:
        print("\n[+] FLAG:", resp["flag"])
    else:
        print("    Response:", resp)
else:
    print("[-] Could not find privkey! Something is still wrong.")
