"""Client: connects to the server, does the DH key exchange, then lets the
user send encrypted text messages and files.

Usage:  python client.py [host] [port]
"""
import os
import socket
import sys

from aes_utils import encrypt, decrypt
from common import send_msg, recv_msg, key_exchange

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5000


def send_text(sock, key, text):
    send_msg(sock, encrypt(key, b"T" + text.encode()))
    print("Server replied:", decrypt(key, recv_msg(sock)).decode())


def send_file(sock, key, path):
    name = os.path.basename(path).encode()
    with open(path, "rb") as f:
        content = f.read()
    payload = b"F" + len(name).to_bytes(2, "big") + name + content
    send_msg(sock, encrypt(key, payload))
    print("Server replied:", decrypt(key, recv_msg(sock)).decode())


def main():
    with socket.create_connection((HOST, PORT)) as sock:
        key = key_exchange(sock, is_client=True)
        print("Key exchange done - secure channel ready.\n")

        while True:
            print("1) Send text   2) Send file   3) Quit")
            choice = input("Choice: ").strip()
            if choice == "1":
                send_text(sock, key, input("Message: "))
            elif choice == "2":
                path = input("File path: ").strip()
                if os.path.isfile(path):
                    send_file(sock, key, path)
                else:
                    print("File not found.")
            elif choice == "3":
                send_msg(sock, encrypt(key, b"Q"))
                break


if __name__ == "__main__":
    main()
