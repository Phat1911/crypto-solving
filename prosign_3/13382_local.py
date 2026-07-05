#!/usr/bin/env python3
"""
CryptoHack 'Curveball' challenge - local version using pure Python ECC.
No fastecdsa dependency needed.
"""
from utils import listener
import builtins

# P256 curve parameters
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = -3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

class Point:
    """Simple affine point on a Weierstrass curve y^2 = x^3 + ax + b mod p"""
    def __init__(self, x, y, curve=None):
        self.x = x
        self.y = y
        # Verify point is on P256
        if x is not None and y is not None:
            lhs = pow(y, 2, P)
            rhs = (pow(x, 3, P) + A * x + B) % P
            if lhs != rhs:
                raise ValueError(f"Point ({x}, {y}) is not on the P256 curve")

    def __eq__(self, other):
        if isinstance(other, Point):
            return self.x == other.x and self.y == other.y
        return False

    def __repr__(self):
        return f"Point(0x{self.x:X}, 0x{self.y:X})"

    def __mul__(self, scalar):
        """Point * scalar (double-and-add)"""
        return scalar_mul(scalar, self)

    def __rmul__(self, scalar):
        """scalar * Point"""
        return scalar_mul(scalar, self)

# Point at infinity
INF = Point.__new__(Point)
INF.x = None
INF.y = None

def point_add(P1, P2):
    if P1.x is None: return P2
    if P2.x is None: return P1
    if P1.x == P2.x and P1.y == (-P2.y) % P:
        return INF
    if P1.x == P2.x and P1.y == P2.y:
        lam = (3 * P1.x * P1.x + A) * pow(2 * P1.y, -1, P) % P
    else:
        lam = (P2.y - P1.y) * pow(P2.x - P1.x, -1, P) % P
    x3 = (lam * lam - P1.x - P2.x) % P
    y3 = (lam * (P1.x - x3) - P1.y) % P
    result = Point.__new__(Point)
    result.x = x3
    result.y = y3
    return result

def scalar_mul(k, pt):
    result = INF
    addend = pt
    k = k % N
    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


# ========== Challenge code (matches CryptoHack original) ==========

FLAG = "crypto{FAKE_FLAG_run_against_remote_for_real_flag}"

G = Point(0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
          0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


class P256Marker:
    """Dummy curve marker to match fastecdsa interface"""
    pass

P256_CURVE = P256Marker()


class Challenge():
    def __init__(self):
        self.before_input = "Welcome to my secure search engine backed by trusted certificate library!\n"
        self.trusted_certs = {
            'www.cryptohack.org': {
                "public_key": Point(0xE9E4EBA2737E19663E993CF62DFBA4AF71C703ACA0A01CB003845178A51B859D, 0x179DF068FC5C380641DB2661121E568BB24BF13DE8A8968EF3D98CCF84DAF4A9),
                "curve": "secp256r1",
                "generator": [G.x, G.y]
            },
            'www.bing.com': {
                "public_key": Point(0x3B827FF5E8EA151E6E51F8D0ABF08D90F571914A595891F9998A5BD49DFA3531, 0xAB61705C502CA0F7AA127DEC096B2BBDC9BD3B4281808B3740C320810888592A),
                "curve": "secp256r1",
                "generator": [G.x, G.y]
            },
            'www.gchq.gov.uk': {
                "public_key": Point(0xDEDFC883FEEA09DE903ECCB03C756B382B2302FFA296B03E23EEDF94B9F5AF94, 0x15CEBDD07F7584DBC7B3F4DEBBA0C13ECD2D2D8B750CBF97438AF7357CEA953D),
                "curve": "secp256r1",
                "generator": [G.x, G.y]
            }
        }

    def search_trusted(self, Q):
        for host, cert in self.trusted_certs.items():
            if Q == cert['public_key']:
                return True, host
        return False, None

    def sign_point(self, g, d):
        return g * d

    def connection_host(self, packet):
        d = packet['private_key']
        if abs(d) == 1:
            return "Private key is insecure, certificate rejected."
        packet_host = packet['host']
        curve = packet['curve']
        x, y = packet['generator']
        g = Point(x, y)
        Q = self.sign_point(g, d)
        cached, host = self.search_trusted(Q)
        if cached:
            return host
        else:
            self.trusted_certs[packet_host] = {
                "public_key": Q,
                "curve": "secp256r1",
                "generator": G
            }
            return "Site added to trusted connections"

    def bing_it(self, s):
        return f"Hey bing! Tell me about {s}"

    #
    # This challenge function is called on your input, which must be JSON
    # encoded
    #
    def challenge(self, your_input):
        host = self.connection_host(your_input)
        if host == "www.bing.com":
            return self.bing_it(FLAG)
        else:
            return self.bing_it(host)


builtins.Challenge = Challenge
listener.start_server(port=13382)
