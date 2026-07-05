import socket
import json

s = socket.socket()
s.settimeout(5)
s.connect(('socket.cryptohack.org', 13382))

# Read welcome message
print(s.recv(4096).decode())

# Send a test payload (using the real P256 generator)
gx = 15520159875205514130255899098025123715054849599936616868365830290232639266390
gy = 35332573964480432986660122673305225849700662492297568815244635356931754804527

payload = {"host": "test", "private_key": 2, "generator": [gx, gy], "curve": "secp256r1"}
s.send(json.dumps(payload).encode() + b'\n')

import time
time.sleep(1)
print(s.recv(4096).decode())

s.close()
