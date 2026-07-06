import socket
import json
import itertools
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256

p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
F = GF(p)
a = F(-3)

target_prod = 2**256

print("[+] Phase 1: Precomputing invalid curves and points...")
sys.stdout.flush()
precomputed = []
prod = 1
primes = set()

while prod < target_prod:
    b_prime = F.random_element()
    try:
        E_prime = EllipticCurve(F, [a, b_prime])
    except:
        continue
    
    order = E_prime.order()
    factors = []
    
    for q, e in factor(order, limit=100000):
        if 10000 < q < 100000 and q not in primes:
            factors.append(q)
            
    for q in factors:
        if prod >= target_prod:
            break
            
        print(f"[*] Found good prime: {q}")
        sys.stdout.flush()
        
        while True:
            P_rand = E_prime.random_point()
            G_prime = (order // q) * P_rand
            if G_prime != E_prime(0):
                break
                
        precomputed.append((q, G_prime))
        primes.add(q)
        prod *= q

print(f"\n[+] Precomputed {len(precomputed)} primes. Product > 2^256.")
sys.stdout.flush()

print("[+] Phase 2: Connecting to server to execute attack...")
sys.stdout.flush()
class Conn:
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect(("socket.cryptohack.org", 13419))
        self.buffer = b""

    def read_line(self):
        while b"\n" not in self.buffer:
            chunk = self.s.recv(1024)
            if not chunk:
                raise ConnectionError("Connection closed by server")
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\n", 1)
        return line.decode()

    def send_line(self, line):
        self.s.sendall((line + "\n").encode())

conn = Conn()

conn.read_line() # Eavesdropping...
conn.read_line() # client initiating key agreement :
client_pub_line = conn.read_line()
server_pub_line = conn.read_line()
flag_line = conn.read_line()

client_x = int(client_pub_line.split("x=")[1].split(",")[0])
client_y = int(client_pub_line.split("y=")[1].split(")")[0])
server_x = int(server_pub_line.split("x=")[1].split(",")[0])
server_y = int(server_pub_line.split("y=")[1].split(")")[0])
enc_flag_hex = flag_line.split("server->client : ")[1].strip()
enc_flag_bytes = bytes.fromhex(enc_flag_hex)
flag_iv = enc_flag_bytes[:16]
flag_ct = enc_flag_bytes[16:]

print(f"[+] Got client public key: ({client_x}, {client_y})")
print(f"[+] Got server public key: ({server_x}, {server_y})")
sys.stdout.flush()

print("[+] Phase 3: Sending precomputed points to server...")
sys.stdout.flush()
queries_data = []

for q, G_prime in precomputed:
    qx_hex = hex(int(G_prime[0]))
    qy_hex = hex(int(G_prime[1]))
    
    conn.send_line(json.dumps({"option": "start_key_exchange", "Qx": qx_hex, "Qy": qy_hex, "ciphersuite": "ECDHE_P256_WITH_AES_128"}))
    conn.read_line() 
    
    conn.send_line(json.dumps({"option": "get_test_message"}))
    resp2 = json.loads(conn.read_line())
    
    test_msg_bytes = bytes.fromhex(resp2["msg"])
    test_iv = test_msg_bytes[:16]
    test_ct = test_msg_bytes[16:]
    
    queries_data.append((q, G_prime, test_iv, test_ct))

print("[+] All queries completed successfully! Connection can now safely drop.")
sys.stdout.flush()

print("[+] Phase 4: Offline brute-forcing remainders...")
sys.stdout.flush()
primes_list = []
remainders = []

for q, G_prime, test_iv, test_ct in queries_data:
    print(f"    [-] Brute-forcing remainder modulo {q}...")
    sys.stdout.flush()
    found = False
    
    K = G_prime
    for k in range(1, q):
        shared_x = int(K[0])
        aes_key = sha256(str(shared_x).encode()).digest()[:16]
        cipher = AES.new(aes_key, AES.MODE_CBC, test_iv)
        decrypted = cipher.decrypt(test_ct)
        
        if b"SERVER_TEST_MESSAGE" in decrypted:
            print(f"    [+] Found remainder! s = {k} or {-k % q} mod {q}")
            sys.stdout.flush()
            primes_list.append(q)
            remainders.append(k)
            found = True
            break
        K += G_prime
        
    if not found:
        print("    [!] Could not find remainder. Something is mathematically wrong.")
        sys.exit(1)

print("\n[+] Phase 5: Disambiguating signs to find the correct private key...")
sys.stdout.flush()

E_256 = EllipticCurve(F, [a, F(0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B)])
Server_Pub = E_256(server_x, server_y)
G_x = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
G_y = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
G_256 = E_256(G_x, G_y)

prod_all = 1
for q in primes_list:
    prod_all *= q

C = [ ( (prod_all // q) * inverse_mod(prod_all // q, q) ) % prod_all for q in primes_list ]
cands = [ (r, q - r) for r, q in zip(remainders, primes_list) ]

true_s = None
count = 0
total_combinations = 2**len(primes_list)

for c in itertools.product(*cands):
    count += 1
    if count % 10000 == 0:
        print(f"    [-] Checked {count} / {total_combinations} combinations...")
        sys.stdout.flush()
    
    s_cand = sum(x * y for x, y in zip(c, C)) % prod_all
    
    if s_cand * G_256 == Server_Pub:
        true_s = s_cand
        break

if true_s is None:
    print("[-] Could not find correct s. Something went wrong.")
    sys.exit(1)

print(f"\n[+] Recovered true server private key s: {true_s}")
sys.stdout.flush()

Client_Pub = E_256(client_x, client_y)
Shared_Flag_Point = true_s * Client_Pub

flag_key = sha256(str(int(Shared_Flag_Point[0])).encode()).digest()[:16]
cipher_flag = AES.new(flag_key, AES.MODE_CBC, flag_iv)
flag = unpad(cipher_flag.decrypt(flag_ct), 16)
print(f"\n[+] FLAG: {flag.decode()}")
sys.stdout.flush()
