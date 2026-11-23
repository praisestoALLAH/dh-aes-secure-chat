"""Shared networking helpers: every message is sent as  [4-byte length][data]."""
import socket
import struct

import dh
from aes_utils import derive_aes_key


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
