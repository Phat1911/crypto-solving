import socket
import json
import re
from Crypto.Cipher import AES
from hashlib import sha256
from operator import xor

p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
prime, b_val = 1229, 1
E = EllipticCurve(GF(p), [-3, b_val])
N = E.order()

# Find a point of order 1229
while True:
    G = E.random_element()
    Q_m = (N // prime) * G
    if Q_m != E(0):
        break

print("[*] Connecting to server...")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('socket.cryptohack.org', 13419))

f = s.makefile('rw', encoding='utf-8')

for _ in range(5):
    f.readline()

# Send Q_m to server
req = json.dumps({
    "option": "start_key_exchange",
    "Qx": hex(int(Q_m[0])),
    "Qy": hex(int(Q_m[1])),
    "ciphersuite": "ECDHE_P256_WITH_AES_128"
}) + "\n"
f.write(req)
f.flush()
f.readline()

# Request test message
req_test = json.dumps({"option": "get_test_message"}) + "\n"
f.write(req_test)
f.flush()

resp_test = json.loads(f.readline())
test_msg = bytes.fromhex(resp_test["msg"])
iv = test_msg[:16]
ciphertext = test_msg[16:]

curr = Q_m
found_k = None

for k in range(1, prime):
    key = sha256(str(int(curr[0])).encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext[:16])
    pt_block = bytes(xor(x, y) for x, y in zip(decrypted, iv))
    
    # Check if pt_block looks printable or matches our target
    # Let's count printable characters
    printables = sum(32 <= c < 127 for c in pt_block)
    if printables >= 12:
        print(f"k={k}: {pt_block}")
        
    if pt_block == b"SERVER_TEST_MESS":
        found_k = k
        break
    curr = curr + Q_m

print("Found k:", found_k)
s.close()
