"""Two-way encrypted chat used by BOTH the server and the client.

Once the Diffie-Hellman key exchange is finished, both programs hold the same
AES key, so they can run exactly the same chat code. Each side has:
  * a background thread that waits for incoming messages (receive_loop), and
  * the main thread that reads what the user types and sends it.
This way either side can send a message at any time.

Every frame on the network is  [4-byte length][nonce + AES-GCM ciphertext + tag].
After decryption the first byte tells what it is:
    b"T" = text message,  b"F" = file,  b"Q" = quit
"""
import os
import threading

from aes_utils import encrypt, decrypt
from common import send_msg, recv_msg

SAVE_DIR = "received_files"


def show_hex(label, data, limit=96):
    """Print encrypted bytes as hex so we can SEE what travels over the network.
    Long data (files) is cut after 'limit' bytes to keep the screen readable."""
    text = data[:limit].hex()
    if len(data) > limit:
        text += f"... ({len(data)} bytes in total)"
    print(f"  [{label}] {text}")


def send_text(sock, key, text):
    encrypted = encrypt(key, b"T" + text.encode())     # 'T' marks a text message
    show_hex("encrypted, sent    ", encrypted)
    send_msg(sock, encrypted)


def send_file(sock, key, path):
    name = os.path.basename(path).encode()
    with open(path, "rb") as f:
        content = f.read()
    # payload = 'F' + 2-byte name length + file name + file content
    payload = b"F" + len(name).to_bytes(2, "big") + name + content
    encrypted = encrypt(key, payload)
    show_hex("encrypted, sent    ", encrypted)
    send_msg(sock, encrypted)
    print(f"  File '{name.decode()}' sent ({len(content)} bytes)")


def receive_loop(sock, key, peer, done):
    """Runs in a background thread: receive, decrypt and display messages."""
    while True:
        try:
            raw = recv_msg(sock)                        # encrypted bytes from the network
        except (ConnectionError, OSError):
            break
        print()
        show_hex("encrypted, received", raw)            # what an eavesdropper would see
        data = decrypt(key, raw)                        # raises an error if data was changed
        kind, body = data[:1], data[1:]

        if kind == b"T":                                # text message
            print(f"{peer}: {body.decode()}")
        elif kind == b"F":                              # file
            name_len = int.from_bytes(body[:2], "big")
            # basename() removes any folder part, so the peer cannot write outside SAVE_DIR
            name = os.path.basename(body[2:2 + name_len].decode())
            content = body[2 + name_len:]
            os.makedirs(SAVE_DIR, exist_ok=True)
            with open(os.path.join(SAVE_DIR, name), "wb") as f:
                f.write(content)
            print(f"{peer} sent file '{name}' ({len(content)} bytes) -> saved in {SAVE_DIR}/")
        elif kind == b"Q":                              # peer left
            print(f"{peer} left the chat. Press Enter to exit.")
            break
        print("> ", end="", flush=True)
    done.set()


def chat(sock, key, peer):
    """Main loop: read the user's input and send it encrypted."""
    done = threading.Event()
    threading.Thread(target=receive_loop, args=(sock, key, peer, done), daemon=True).start()
    print("Type a message and press Enter to send it.")
    print("Commands:  /file <path>  sends a file     /quit  ends the chat\n")

    while not done.is_set():
        line = input("> ").strip()
        if done.is_set():
            break
        if line == "/quit":
            send_msg(sock, encrypt(key, b"Q"))
            break
        elif line.startswith("/file "):
            path = line[6:].strip().strip('"')
            if os.path.isfile(path):
                send_file(sock, key, path)
            else:
                print("  File not found.")
        elif line:
            send_text(sock, key, line)
