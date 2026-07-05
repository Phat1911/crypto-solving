from sage.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib

# Curve params from source
p = 0xa15c4fb663a578d8b2496d3151a946119ee42695e18e13e90600192b1d0abdbb6f787f90c8d102ff88e284dd4526f5f6b6c980bf88f1d0490714b67e8a2a2b77
a = 0x5e009506fcc7eff573bc960d88638fe25e76a9b6c7caeea072a27dcd1fa46abb15b7b6210cf90caba982893ee2779669bac06e267013486b22ff3e24abae2d42
b = 0x2ce7d1ca4493b0977f088f6d30d9241f8048fdea112cc385b793bce953998caae680864a7d3aa437ea3ffd1441ca3fb352b0b710bb3f053e980e503be9a7fece

E = EllipticCurve(GF(p), [a, b])

# From output.txt
gx = 3034712809375537908102988750113382444008758539448972750581525810900634243392172703684905257490982543775233630011707375189041302436945106395617312498769005
gy = 4986645098582616415690074082237817624424333339074969364527548107042876175480894132576399611027847402879885574130125050842710052291870268101817275410204850
G = E(gx, gy)

ax = 4748198372895404866752111766626421927481971519483471383813044005699388317650395315193922226704604937454742608233124831870493636003725200307683939875286865
ay = 2421873309002279841021791369884483308051497215798017509805302041102468310636822060707350789776065212606890489706597369526562336256272258544226688832663757
A = E(ax, ay)

iv_hex = '719700b2470525781cc844db1febd994'
ct_hex = '335470f413c225b705db2e930b9d460d3947b3836059fb890b044e46cbb343f0'

def smart_attack(G, Pub, p):
    # 1. Extract the original elliptic curve E
    E = G.curve()

    # 2. Lift the curve into the p-adic field Qp(p, 2)
    # This creates a new curve using the original a and b parameters converted to integers (ZZ)
    Eqp = EllipticCurve(Qp(p, 2), [ZZ(t) for t in E.a_invariants()])

    # 3. Lift the Generator point G into the p-adic curve Eqp
    # lift_x calculates a point on Eqp using G's X-coordinate. It returns two possible points; we grab the first [0].
    G_Qp = Eqp.lift_x(ZZ(G.xy()[0]), all=True)[0]
    # Check if we grabbed the correct one by comparing its Y-coordinate with the original G
    if GF(p)(G_Qp.xy()[1]) != G.xy()[1]:
        G_Qp = -G_Qp  # If it doesn't match, negate the point to get the other one
        
    # 4. Lift the Public Key into the p-adic curve Eqp (same process as above)
    Pub_Qp = Eqp.lift_x(ZZ(Pub.xy()[0]), all=True)[0]
    if GF(p)(Pub_Qp.xy()[1]) != Pub.xy()[1]:
        Pub_Qp = -Pub_Qp
        
    p_G = p * G_Qp
    p_Pub = p * Pub_Qp
    
    x1, y1 = p_G.xy()
    x2, y2 = p_Pub.xy()
    
    phi_G = -(x1 / y1)
    phi_Pub = -(x2 / y2)
    
    return ZZ(phi_Pub / phi_G) % p

print("[*] Running Smart's Attack to recover Alice's private key...")
nA = smart_attack(G, A, p)
print(f"[+] Recovered Private Key: {nA}")

# Bob's public key from source
b_x = 0x7f0489e4efe6905f039476db54f9b6eac654c780342169155344abc5ac90167adc6b8dabacec643cbe420abffe9760cbc3e8a2b508d24779461c19b20e242a38
b_y = 0xdd04134e747354e5b9618d8cb3f60e03a74a709d4956641b234daa8a65d43df34e18d00a59c070801178d198e8905ef670118c15b0906d3a00a662d3a2736bf
B = E(b_x, b_y)

print("[*] Calculating shared secret...")
S = B * nA
secret = S.xy()[0]

print("[*] Deriving AES key...")
sha1 = hashlib.sha1()
sha1.update(str(secret).encode('ascii'))
key = sha1.digest()[:16]

iv = bytes.fromhex(iv_hex)
ciphertext = bytes.fromhex(ct_hex)

print("[*] Decrypting flag...")
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(ciphertext), 16)

print(f"\n[SUCCESS] FLAG: {flag.decode('utf-8')}")
