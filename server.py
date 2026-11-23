"""Server: waits for a client, does the Diffie-Hellman key exchange and then
starts a two-way encrypted chat.

Usage:  python server.py [port]
"""
import socket
import sys

from common import key_exchange
from chat import chat

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5000


def main():
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", PORT))
        server.listen(1)
        print(f"Server listening on port {PORT} ...")
        conn, addr = server.accept()
        print(f"Client connected from {addr[0]}")

        with conn:
            key = key_exchange(conn, is_client=False)   # DH -> shared AES key
            print("Key exchange done - secure channel ready.\n")
            chat(conn, key, peer="Client")
    print("Connection closed.")


if __name__ == "__main__":
    main()
