import random
from Crypto.Util.number import getPrime
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def egcd(a, b):
    # returns (g, x, y) such that a*x + b*y == g
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def mod_inverse(a, m):
    # returns d such that (a * d) % m == 1, raises if a and m are not coprime
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("Modular inverse does not exist")
    else:
        return x % m


def dh_generate_private(q):
    # picks a random exponent in [2, q-2]
    return random.randint(2, q - 2)

def dh_public_value(g, x, q):
    # returns g^x mod q
    return pow(g, x, q)

def dh_shared_secret(peer_public, x, q):
    # returns peer_public^x mod q
    return pow(peer_public, x, q)

def derive_aes_key(shared_secret_int):
    # converts the shared secret int to bytes, hashes with sha-256, truncates digest to 16 bytes for an AES-128 key
    num_bytes = (shared_secret_int.bit_length() + 7) // 8
    if num_bytes == 0:
        num_bytes = 1
    secret_bytes = shared_secret_int.to_bytes(num_bytes, byteorder="big")
    digest = SHA256.new(secret_bytes).digest()
    return digest[:16]

def aes_cbc_encrypt(key, plaintext_bytes):
    # generates a random 16-byte IV, pads plaintext with PKCS7, encrypts, returns iv + ciphertext
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plaintext_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return iv + ciphertext

def aes_cbc_decrypt(key, iv_and_ciphertext):
    # splits off the first 16 bytes as the iv, decrypts the rest, removes PKCS7 padding
    iv = iv_and_ciphertext[:16]
    ciphertext = iv_and_ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    return unpad(padded, AES.block_size)

DH_1024_Q_HEX = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371"
DH_1024_G_HEX = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5"

def dh_real_params():
    # converts the exact IETF hex constant to an integer, no truncation
    q = int(DH_1024_Q_HEX, 16)
    g = int(DH_1024_G_HEX, 16)
    return q, g

def _rsa_generate_key_material(bits=512, e=65537):
    # picks two large random primes p and q, computes n and phi
    # retries if e and phi are not coprime (mod_inverse would raise)
    # returns the raw p, q, n, phi, d pieces so callers (and tests) can inspect the setup
    while True:
        p = getPrime(bits)
        q = getPrime(bits)
        n = p * q
        phi = (p - 1) * (q - 1)
        try:
            d = mod_inverse(e, phi)
        except Exception:
            continue
        break
    return p, q, n, phi, d

def rsa_generate_keypair(bits=512, e=65537):
    # generates the key material and returns just the public/private keypair
    p, q, n, phi, d = _rsa_generate_key_material(bits, e)
    return ((e, n), (d, n))

def rsa_encrypt(m, pub):
    # textbook rsa encryption, c = m^e mod n
    e, n = pub
    return pow(m, e, n)

def rsa_decrypt(c, priv):
    # textbook rsa decryption, m = c^d mod n
    d, n = priv
    return pow(c, d, n)

def rsa_sign(m, priv):
    # textbook rsa signing, s = m^d mod n
    d, n = priv
    return pow(m, d, n)

def rsa_verify(s, pub):
    # textbook rsa verification, m = s^e mod n
    e, n = pub
    return pow(s, e, n)