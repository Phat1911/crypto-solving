import socket
import json
import time

# Test different CryptoHack socket ports to see if ANY work
# Common challenge ports from CryptoHack
test_ports = [13370, 13371, 13372, 13373, 13380, 13381, 13382]

for port in test_ports:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(('socket.cryptohack.org', port))
        time.sleep(0.5)
        try:
            data = s.recv(4096)
            print(f"Port {port}: CONNECTED, received {len(data)} bytes: {data[:100]}")
        except ConnectionResetError:
            print(f"Port {port}: CONNECTED then RESET (same issue)")
        except socket.timeout:
            print(f"Port {port}: CONNECTED but no data (timeout)")
        s.close()
    except ConnectionRefusedError:
        print(f"Port {port}: REFUSED (not running)")
    except socket.timeout:
        print(f"Port {port}: TIMEOUT (can't reach)")
    except Exception as e:
        print(f"Port {port}: ERROR: {e}")
