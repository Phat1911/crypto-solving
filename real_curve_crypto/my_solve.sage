from mpmath import mp
import json
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import unpad

# 200 decimal places of precision, just like the challenge source
mp.dps = 200

def get_1d_index(x, y):
    """
    Integrates 1/y dx to find the 'Magic Distance'.
    """
    index = mp.quad(lambda t: 1/mp.sqrt(t**3 - t), [x, mp.inf])
    if y < 0:
        return -index
    return index

def solve():
    # 1. Read the data
    with open('output_8d82e413d29d7810ee8eff5d1226453d.txt', 'r') as f:
        data = json.load(f)

    gx = mp.mpf(data['gx'])
    gy = mp.mpf(data['gy'])
    px = mp.mpf(data['px'])
    py = mp.mpf(data['py'])
    ciphertext = bytes.fromhex(data['ciphertext'])
    iv = bytes.fromhex(data['iv'])

    print("[*] Calculating the 'Magic Distances' (integrals)... This might take 5-10 seconds.")
    dist_G = get_1d_index(gx, gy)
    dist_P = get_1d_index(px, py)
    
    # Calculate the period (the maximum distance before it wraps around, like 360 degrees on a circle)
    MAX_BUFFER_SIZE = 2 * mp.quad(lambda t: 1/mp.sqrt(t**3 - t), [1, mp.inf])

    print(f"[+] dist_G = {dist_G}")
    print(f"[+] dist_P = {dist_P}")
    print(f"[+] MAX_BUFFER = {MAX_BUFFER_SIZE}")

    # 2. Set up the equation
    # We know that:  dist_P = N * dist_G - k * MAX_BUFFER_SIZE
    # Rearranging:   N * (dist_G / MAX_BUFFER_SIZE) - k = (dist_P / MAX_BUFFER_SIZE)
    
    alpha = dist_G / MAX_BUFFER_SIZE
    beta = dist_P / MAX_BUFFER_SIZE
    
    # We multiply by a large power of 2 to turn these decimals into integers for the Lattice
    SCALE = 2**300 
    alpha_int = int(alpha * SCALE)
    beta_int = int(beta * SCALE)
    
    # 3. Use LLL algorithm to solve for N
    print("[*] Setting up the Lattice to find the Private Key N...")
    W = 2**128  # Weight for N (since we know the AES key N is 16 bytes / 128 bits)
    
    M = Matrix(ZZ, [
        [SCALE,     0, 0],
        [alpha_int, 1, 0],
        [beta_int,  0, W]
    ])
    
    reduced = M.LLL()
    
    N_found = None
    for row in reduced:
        # We look for the row that has our W (or -W) in the last column
        if row[2] == W or row[2] == -W:
            N_found = abs(row[1])
            break
            
    if not N_found:
        print("[-] Failed to find N.")
        return
        
    print(f"\n[+] BOOM! Private Key N found: {N_found}")
    
    # 4. Decrypt the flag
    key = long_to_bytes(int(N_found))
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), 16)
    
    print(f"\n[+] FLAG: {plaintext.decode()}")

solve()
