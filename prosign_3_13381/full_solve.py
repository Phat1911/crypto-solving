import json
import hashlib
from pwn import *
from Crypto.Util.number import bytes_to_long, inverse

# --- ECC parameters for NIST P-192 ---
p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
order = 6277101735386680763835789423176059013767194773182842284081
a = -3
b = 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1
Gx = 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012
Gy = 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811

# Pure Python elliptic curve math to avoid depending on external ecdsa module
def point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2: return None
    if x1 == x2:
        l = (3 * x1 * x1 + a) * inverse(2 * y1, p) % p
    else:
        l = (y2 - y1) * inverse(x2 - x1, p) % p
    x3 = (l * l - x1 - x2) % p
    y3 = (l * (x1 - x3) - y1) % p
    return (x3, y3)

def point_mul(k, P):
    R = None
    addend = P
    while k:
        if k & 1:
            R = point_add(R, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return R

G = (Gx, Gy)

def sha1(data):
    sha1_hash = hashlib.sha1()
    sha1_hash.update(data)
    return sha1_hash.digest()

# --- Connect and Solve ---
print("[*] Connecting to the server...")
conn = remote('socket.cryptohack.org', 13381)
conn.recvline() # Consume the welcome message

# 1. Ask for signature
request_sign = {"option": "sign_time"}
conn.sendline(json.dumps(request_sign).encode())

# 2. Receive and parse
response = json.loads(conn.recvline().decode())
msg = response['msg']
r = int(response['r'], 16)
s = int(response['s'], 16)

print(f"[*] Received msg: {msg}")

# Extract seconds (n) from the msg "Current time is m:n"
n_local = int(msg.split(":")[1])
if n_local == 0:
    n_local = 60 # Handle edge case where seconds is 0, since k is modulo n_local, but range is 1 to n. Let's brute force up to 60 to be safe.
z = bytes_to_long(sha1(msg.encode()))

# 3. Brute force k
found_k = None
for k in range(1, 60): # Max seconds is 59
    point = point_mul(k, G)
    if point is not None and point[0] % order == r:
        found_k = k
        break

if not found_k:
    print("[-] Could not find k!")
    exit(1)

print(f"[+] Found k: {found_k}")

# 4. Recover private key
private_key = (s * found_k - z) * inverse(r, order) % order
print(f"[+] Recovered private key: {hex(private_key)}")

# 5. Forge signature for "unlock"
unlock_msg = "unlock"
unlock_z = bytes_to_long(sha1(unlock_msg.encode()))

k_forge = 1337
R_forge = point_mul(k_forge, G)
r_forge = R_forge[0] % order
s_forge = inverse(k_forge, order) * (unlock_z + r_forge * private_key) % order

# 6. Send payload
payload = {
    "option": "verify",
    "msg": unlock_msg,
    "r": hex(r_forge),
    "s": hex(s_forge)
}

print("[*] Sending forged signature...")
conn.sendline(json.dumps(payload).encode())

# Get the flag!
final_response = conn.recvline().decode()
print("\n[+] Final Server Response:")
print(final_response)
