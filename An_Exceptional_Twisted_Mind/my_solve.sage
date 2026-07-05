import socket
import json

p = 115792089237316195423570985008687907853269984665640564039457584007913129639747
a = -3
b = 152961
order = 115792089237316195423570985008687907853233080465625507841270369819257950283813

# R = Z_{p^2}
R = IntegerModRing(p^2)
E_p2 = EllipticCurve(R, [a, b])
E_p = EllipticCurve(GF(p), [a, b])
N_p = E_p.order()

def lift_sqrt(y_sqr, p):
    y_sqr_p = GF(p)(y_sqr)
    y0 = int(y_sqr_p.sqrt())
    diff = int(y_sqr) - y0^2
    k = (diff // p) * inverse_mod(2 * y0, p) % p
    return y0 + k * p

# --- 1. Find a valid point P on E(Z_{p^2}) ---
print("[*] Finding a valid point P on E(Z_{p^2})...")
while True:
    x_val = R.random_element()
    y_sqr = x_val^3 + a*x_val + b
    if GF(p)(y_sqr).is_square():
        y_val = lift_sqrt(y_sqr, p)
        P = E_p2(x_val, y_val)
        break

print(f"[+] Found P: ({P[0]}, {P[1]})")

# --- 2. Connect to Server ---
print("[*] Connecting to server...")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('socket.cryptohack.org', 13417))

# Create a file object for buffered reading
f = s.makefile('rw', encoding='utf-8')

# Consume welcome message
print(f.readline().strip())
print(f.readline().strip())
print(f.readline().strip())

# Send x0
req = json.dumps({"option": "get_pubkey", "x0": str(P[0])}) + "\n"
f.write(req)
f.flush()

resp = json.loads(f.readline())
if "error" in resp:
    print("[-] Error from server:", resp["error"])
    s.close()
    exit(1)

Q_x = int(resp["pubkey"])
print(f"[+] Received Q_x: {Q_x}")

# --- 3. Reconstruct Q on E(Z_{p^2}) ---
y_sqr_Q = Q_x^3 + a*Q_x + b
y_val_Q = lift_sqrt(y_sqr_Q, p)

# There are two possible points (Q or -Q)
candidates = [E_p2(Q_x, y_val_Q), E_p2(Q_x, -y_val_Q)]

# --- 4. Perform the generalized Smart's Attack ---
print("[*] Performing Smart's Attack...")

# Define p-adic curve for Smart's attack using standard parameters directly
Eqp = EllipticCurve(Qp(p, 2), [a, b])

# Instantiate G directly in Qp
G_Qp = Eqp(ZZ(P[0]), ZZ(P[1]))

final_key = None

for Q_cand in candidates:
    # Instantiate Q candidate directly in Qp
    Pub_Qp = Eqp(ZZ(Q_cand[0]), ZZ(Q_cand[1]))

    # Project to kernel
    P0 = N_p * G_Qp
    Pub0 = N_p * Pub_Qp

    x1, y1 = P0.xy()
    x2, y2 = Pub0.xy()

    phi_G = -(x1 / y1)
    phi_Pub = -(x2 / y2)

    res = phi_Pub / phi_G
    d = ZZ(res) % p

    # Verify key candidate locally using [key]*P mod p^2
    for key in [d, (order - d) % order]:
        try:
            if (key * P)[0] == Q_x:
                final_key = key
                break
        except Exception:
            continue
    if final_key is not None:
        break

if final_key is not None:
    print(f"[+] Verified Private Key locally: {final_key}")
    print("[*] Sending key to server...")
    # Send privkey as an integer directly to avoid python's string formatting TypeError
    req_flag = json.dumps({"option": "get_flag", "privkey": int(final_key)}) + "\n"
    f.write(req_flag)
    f.flush()
    
    flag_resp = json.loads(f.readline())
    if "flag" in flag_resp:
        print(f"\n[SUCCESS] FLAG: {flag_resp['flag']}")
        s.close()
        exit(0)
    else:
        print("[-] Server rejected the key:", flag_resp)
else:
    print("[-] Failed to find the private key locally.")

s.close()
