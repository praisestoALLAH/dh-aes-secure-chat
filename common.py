"""Shared networking helpers: every message is sent as  [4-byte length][data]."""
import os
import struct
import threading

import dh
from aes_utils import derive_aes_key, encrypt, decrypt


def send_msg(sock, data):
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf += chunk
    return buf


def recv_msg(sock):
    (length,) = struct.unpack(">I", recv_exact(sock, 4))
    return recv_exact(sock, length)


def key_exchange(sock, is_client):
    """Run Diffie-Hellman over the socket and return the 32-byte AES key."""
    private = dh.generate_private_key()
    public = dh.generate_public_key(private)

    if is_client:                                   # client sends first
        send_msg(sock, dh.to_bytes(public))
        other_public = dh.from_bytes(recv_msg(sock))
    else:                                           # server receives first
        other_public = dh.from_bytes(recv_msg(sock))
        send_msg(sock, dh.to_bytes(public))

    secret = dh.compute_shared_secret(private, other_public)
    return derive_aes_key(dh.to_bytes(secret))


SAVE_DIR = "received_files"


def receive_loop(sock, key):
    """Runs in a background thread: decrypts everything the other side sends."""
    while True:
        try:
            data = decrypt(key, recv_msg(sock))      # wait for an encrypted frame
        except (ConnectionError, OSError):
            break
        kind, body = data[:1], data[1:]              # first byte = message type

        if kind == b"T":                             # text message
            print("\n[Peer]", body.decode())
        elif kind == b"F":                           # file: 2-byte name length, name, content
            name_len = int.from_bytes(body[:2], "big")
            name = os.path.basename(body[2:2 + name_len].decode())   # strip any folders
            os.makedirs(SAVE_DIR, exist_ok=True)
            with open(os.path.join(SAVE_DIR, name), "wb") as f:
                f.write(body[2 + name_len:])
            print(f"\n[File received] saved as {SAVE_DIR}/{name}")
        elif kind == b"Q":                           # peer left
            break
    print("\nPeer disconnected. Press Enter to exit.")


def chat(sock, key):
    """Two-way chat: the receiving thread prints incoming messages while this
    function reads what the user types and sends it encrypted."""
    threading.Thread(target=receive_loop, args=(sock, key), daemon=True).start()
    print("Type a message and press Enter. Commands:  /file <path>   /quit\n")
    try:
        while True:
            line = input()
            if line == "/quit":
                send_msg(sock, encrypt(key, b"Q"))
                break
            elif line.startswith("/file "):
                path = line[6:].strip().strip('"')
                if not os.path.isfile(path):
                    print("File not found.")
                    continue
                name = os.path.basename(path).encode()
                with open(path, "rb") as f:
                    content = f.read()
                send_msg(sock, encrypt(key, b"F" + len(name).to_bytes(2, "big") + name + content))
                print("File sent.")
            elif line:
                send_msg(sock, encrypt(key, b"T" + line.encode()))
    except (EOFError, OSError):
        pass
