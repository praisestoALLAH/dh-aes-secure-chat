"""Diffie-Hellman key exchange, implemented by hand (no DH library used).

Both parties agree on two PUBLIC numbers:
    p - a large prime (here the 2048-bit prime from RFC 3526, group 14)
    g - a generator (here 2)

Each party then:
    1. picks a random PRIVATE number           (a for Alice, b for Bob)
    2. computes a PUBLIC number                A = g^a mod p,  B = g^b mod p
    3. sends its public number to the other side
    4. computes the shared secret              K = B^a mod p = A^b mod p = g^(ab) mod p

An eavesdropper sees p, g, A and B, but computing a or b from them is the
discrete logarithm problem, which is infeasible for a 2048-bit prime.
"""
import secrets

P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
G = 2
KEY_BYTES = 256  # a 2048-bit number takes 256 bytes


def generate_private_key():
    """Random secret exponent. 'secrets' uses the OS cryptographic random generator."""
    return secrets.randbelow(P - 3) + 2          # 2 <= private <= P-2


def generate_public_key(private_key):
    """A = g^a mod p  (pow with 3 arguments does fast modular exponentiation)."""
    return pow(G, private_key, P)


def compute_shared_secret(private_key, other_public_key):
    """K = B^a mod p. Both sides end up with the same number."""
    if not 2 <= other_public_key <= P - 2:       # basic sanity check on received value
        raise ValueError("Invalid public key received")
    return pow(other_public_key, private_key, P)


def to_bytes(number):
    return number.to_bytes(KEY_BYTES, "big")


def from_bytes(data):
    return int.from_bytes(data, "big")
