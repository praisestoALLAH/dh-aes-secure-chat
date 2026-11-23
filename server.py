"""Server: waits for a client, does the DH key exchange, then receives
encrypted text messages and files and sends back an encrypted reply.

Usage:  python server.py [port]
"""
import os
import socket
import sys

from aes_utils import encrypt, decrypt
from common import send_msg, recv_msg, key_exchange

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
SAVE_DIR = "received_files"


def main():
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", PORT))
        server.listen(1)
        print(f"Server listening on port {PORT} ...")
        conn, addr = server.accept()
        print(f"Client connected from {addr[0]}")

        with conn:
            key = key_exchange(conn, is_client=False)
            print("Key exchange done - secure channel ready.\n")

            while True:
                try:
                    raw = recv_msg(conn)                  # encrypted bytes
                except ConnectionError:
                    break
                data = decrypt(key, raw)
                kind, body = data[:1], data[1:]

                if kind == b"T":                          # text message
                    print("Client says:", body.decode())
                    send_msg(conn, encrypt(key, b"Message received"))

                elif kind == b"F":                        # file
                    name_len = int.from_bytes(body[:2], "big")
                    name = os.path.basename(body[2:2 + name_len].decode())
                    content = body[2 + name_len:]
                    os.makedirs(SAVE_DIR, exist_ok=True)
                    with open(os.path.join(SAVE_DIR, name), "wb") as f:
                        f.write(content)
                    print(f"Received file '{name}' ({len(content)} bytes)")
                    send_msg(conn, encrypt(key, b"File received"))

                elif kind == b"Q":                        # quit
                    break
    print("Connection closed.")


if __name__ == "__main__":
    main()
