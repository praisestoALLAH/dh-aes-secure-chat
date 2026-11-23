# Diffie-Hellman + AES (IT Security lab, programming task 1)

## Files
- dh.py         - Diffie-Hellman written from scratch
- aes_utils.py  - SHA-256 key derivation + AES-256-GCM encrypt/decrypt
- common.py     - socket helpers and the key-exchange routine
- server.py     - server (receives text and files)
- client.py     - client (menu: send text / send file / quit)

## Run
    pip install -r requirements.txt
    python server.py          # terminal 1
    python client.py          # terminal 2   (python client.py <server-ip> 5000 for another PC)
