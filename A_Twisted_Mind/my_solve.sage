import socket
import json

p = 2**192 - 237
a = -3
b = 1379137549983732744405137513333094987949371790433997718123
order = 6277101735386680763835789423072729104060819681027498877478

# The challenge curve E over GF(p)
E = EllipticCurve(GF(p), [a, b])
N = E.order()
N_twist = 2*(p+1) - N

print(f"[*] Original curve order N: {N}")
print(f"[*] Twisted curve order N_twist: {N_twist}")

# Find smooth factors
bound = 2**40
smooth_N = 1
for P_prime, e in factor(N):
    if P_prime < bound:
        smooth_N *= P_prime**e

smooth_N_twist = 1
for P_prime, e in factor(N_twist):
    if P_prime < bound:
        smooth_N_twist *= P_prime**e

print(f"[*] Smooth part of N: {smooth_N}")
print(f"[*] Smooth part of N_twist: {smooth_N_twist}")
print(f"[*] Product of smooth parts size: {(smooth_N * smooth_N_twist).nbits()} bits")

print("\n[*] Finding smooth point on E(GF(p))...")
P_smooth = (N // smooth_N) * E.random_element()
while P_smooth.is_zero() or P_smooth.order() != smooth_N:
    P_smooth = (N // smooth_N) * E.random_element()
x1 = int(P_smooth[0])

print("[*] Finding smooth point for the twist in E(GF(p^2))...")
Fp2.<u> = GF(p**2)
E2 = EllipticCurve(Fp2, [a, b])

while True:
    x2_val = GF(p).random_element()
    rhs = x2_val**3 + a*x2_val + b
    if not rhs.is_square():
        P2 = E2.lift_x(Fp2(x2_val))
        P_twist_smooth = (N_twist // smooth_N_twist) * P2
        if not P_twist_smooth.is_zero() and P_twist_smooth.order() == smooth_N_twist:
            x2 = int(P_twist_smooth[0])
            break

print(f"[*] Found x1 = {x1}")
print(f"[*] Found x2 = {x2}")

print("\n[*] Connecting to server...")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('socket.cryptohack.org', 13416))

def recvline():
    buf = b""
    while not buf.endswith(b"\n"):
        buf += s.recv(1)
    return buf.decode()

# Consume welcome message
print(recvline().strip())
print(recvline().strip())
print(recvline().strip())

# Send x1
req1 = json.dumps({"option": "get_pubkey", "x0": str(x1)}) + "\n"
s.sendall(req1.encode())
Q1_x = int(json.loads(recvline())["pubkey"])
print(f"[+] Received Q1_x = {Q1_x}")

# Send x2
req2 = json.dumps({"option": "get_pubkey", "x0": str(x2)}) + "\n"
s.sendall(req2.encode())
Q2_x = int(json.loads(recvline())["pubkey"])
print(f"[+] Received Q2_x = {Q2_x}")

print("\n[*] Calculating discrete logs (this will take a minute)...")
Q1 = E.lift_x(GF(p)(Q1_x))
dl1 = discrete_log(Q1, P_smooth, operation='+')
opts_1 = [dl1, (-dl1) % smooth_N]

Q2 = E2.lift_x(Fp2(Q2_x))
dl2 = discrete_log(Q2, P_twist_smooth, operation='+')
opts_2 = [dl2, (-dl2) % smooth_N_twist]

for d1 in opts_1:
    for d2 in opts_2:
        guess = crt([d1, d2], [smooth_N, smooth_N_twist])
        guess = min(guess % order, (order - guess) % order)
        
        req_flag = json.dumps({"option": "get_flag", "privkey": str(guess)}) + "\n"
        s.sendall(req_flag.encode())
        res_str = recvline().strip()
        res = json.loads(res_str)
        if "flag" in res:
            print("\n[+] SUCCESS! FLAG:", res["flag"])
            s.close()
            import sys
            sys.exit(0)

print("\n[-] Failed to find the correct key.")
s.close()
