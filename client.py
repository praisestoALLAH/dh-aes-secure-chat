"""Client: connects to the server, does the Diffie-Hellman key exchange and then
starts a two-way encrypted chat.

Usage:  python client.py [host] [port]
"""
import socket
import sys

from common import key_exchange
from chat import chat

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5000


def main():
    with socket.create_connection((HOST, PORT)) as sock:
        key = key_exchange(sock, is_client=True)        # DH -> shared AES key
        print("Key exchange done - secure channel ready.\n")
        chat(sock, key, peer="Server")
    print("Connection closed.")


if __name__ == "__main__":
    main()
