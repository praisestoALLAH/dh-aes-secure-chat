# Diffie-Hellman + AES (IT Security lab, programming task 1)

Two-way encrypted chat with file transfer between a server and a client.
The Diffie-Hellman key exchange is written from scratch; AES-256-GCM comes from the
`cryptography` library. The encrypted data (hex) is displayed for every message.

## Files
- dh.py         - Diffie-Hellman written from scratch
- aes_utils.py  - SHA-256 key derivation + AES-256-GCM encrypt/decrypt
- common.py     - socket helpers and the key-exchange routine
- chat.py       - two-way chat (send/receive threads, text + files, shows encrypted hex)
- server.py     - server program
- client.py     - client program

## Run
    pip install -r requirements.txt
    python server.py          # terminal 1
    python client.py          # terminal 2   (python client.py <server-ip> 5000 for another PC)

## Using the chat (same on both sides)
    hello                 type text + Enter to send a message
    /file C:\path\x.pdf   send a file (saved by the other side in received_files/)
    /quit                 end the chat
