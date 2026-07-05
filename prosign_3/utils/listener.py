#!/usr/bin/env python3
"""
CryptoHack-compatible listener module for running challenges locally.
Recreated based on the Challenge class interface used by CryptoHack.
"""

import socketserver
import json
import builtins
import traceback


class ChallengeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            challenge = builtins.Challenge()

            # Send the welcome/before_input message
            if hasattr(challenge, 'before_input') and challenge.before_input:
                self.request.sendall(challenge.before_input.encode())

            # Main loop: receive JSON, process, respond
            while True:
                data = b""
                while b"\n" not in data:
                    chunk = self.request.recv(4096)
                    if not chunk:
                        return
                    data += chunk

                # Process each line
                lines = data.split(b"\n")
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        user_input = json.loads(line.decode())
                        result = challenge.challenge(user_input)
                        response = json.dumps({"flag": result}) if isinstance(result, str) else json.dumps(result)
                        self.request.sendall(response.encode() + b"\n")
                    except json.JSONDecodeError:
                        error_msg = json.dumps({"error": "Invalid JSON"})
                        self.request.sendall(error_msg.encode() + b"\n")
                    except Exception as e:
                        traceback.print_exc()
                        error_msg = json.dumps({"error": str(e)})
                        self.request.sendall(error_msg.encode() + b"\n")

        except Exception as e:
            traceback.print_exc()


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def start_server(port=13382):
    host = "0.0.0.0"
    print(f"[*] Challenge server starting on {host}:{port}")
    server = ReusableTCPServer((host, port), ChallengeHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped")
        server.server_close()
