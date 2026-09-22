import helpers

# generate a fresh RSA keypair using the shared helper
pub, priv = helpers.rsa_generate_keypair()
e, n = pub
d, n = priv

# pick a small plaintext integer, well below n since n is a 1024-bit modulus here
m = 42

# encrypt with the public key
c = helpers.rsa_encrypt(m, pub)

# decrypt with the private key
decrypted = helpers.rsa_decrypt(c, priv)

print("//////////rsa keygen / encrypt / decrypt self-test//////////")
print("e =", e)
print("n =", n)
print("d =", d)
print("m (original plaintext) =", m)
print("c (ciphertext) =", c)
print("decrypted result =", decrypted)

# explicit round trip confirmation
if decrypted == m:
    print("MATCH: decrypted value equals original plaintext, round trip succeeded")
else:
    print("MISMATCH: decrypted value does not equal original plaintext")

assert decrypted == m

# fresh keypair for this section, kept independent from other sections
forge_pub, forge_priv = helpers.rsa_generate_keypair()
forge_e, forge_n = forge_pub
forge_d, forge_n = forge_priv

# two small plaintext messages, both less than n
m1 = 12
m2 = 34

# sign both messages with the real private key
s1 = helpers.rsa_sign(m1, forge_priv)
s2 = helpers.rsa_sign(m2, forge_priv)

# attacker only has s1, s2, and the public key from here on, private key is never touched again
# forge a signature for m3 = m1 * m2 mod n by multiplying the known signatures
m3 = (m1 * m2) % forge_n
s3 = (s1 * s2) % forge_n

# verify the forged signature using only the public key
verified = helpers.rsa_verify(s3, forge_pub)

print("--- rsa signature forgery demo ---")
print("m1 =", m1)
print("m2 =", m2)
print("s1 (signature of m1) =", s1)
print("s2 (signature of m2) =", s2)
print("m3 = (m1 * m2) mod n =", m3)
print("s3 = (s1 * s2) mod n (forged signature) =", s3)
print("verified = s3^e mod n =", verified)

if verified == m3:
    print("MATCH: forged signature s3 verifies correctly for m3, and the private key was never used to create s3")
else:
    print("MISMATCH: forged signature did not verify")

assert verified == m3

# fresh keypair for this demo so it stays self contained from the section above
pub2, priv2 = helpers.rsa_generate_keypair()
e2, n2 = pub2
d2, n2 = priv2

# secret key-exchange value the victim encrypts under the public key
m2 = 1234

# victim's ciphertext, this is what the attacker intercepts
c2 = helpers.rsa_encrypt(m2, pub2)

# attacker picks a known blinding factor r, does not need d2 to do this
r = 7

# attacker tampers the ciphertext: c_prime = (c * r^e) mod n
c_prime = (c2 * pow(r, e2, n2)) % n2

# victim (or attacker with access to the real private key in this demo) decrypts c_prime
decrypted2 = helpers.rsa_decrypt(c_prime, priv2)

# expected result per the malleability property: decrypting c_prime yields m * r mod n
expected2 = (m2 * r) % n2

print()
print("rsa malleability: r-multiplication variant")
print("e =", e2)
print("n =", n2)
print("m (original key-exchange value) =", m2)
print("r (attacker-chosen blinding factor) =", r)
print("c (original ciphertext) =", c2)
print("c_prime (tampered ciphertext) =", c_prime)
print("decrypted c_prime =", decrypted2)
print("expected (m * r) mod n =", expected2)

if decrypted2 == expected2:
    print("MATCH: decrypting the tampered ciphertext yields m * r mod n, confirming malleability")
else:
    print("MISMATCH: malleability result did not match expected value")

assert decrypted2 == expected2

# fresh keypair for this demo so it stays separate from the sections above
pub3, priv3 = helpers.rsa_generate_keypair()
e3, n3 = pub3
d3, n3 = priv3

# Bob chooses an unknown secret and encrypts it under Alice's public key.
m3_val = 99
c3 = helpers.rsa_encrypt(m3_val, pub3)

# Mallory does not need to know m3_val: she substitutes ciphertext 1.
# Alice decrypts 1^d mod n = 1, so Mallory knows Alice's resulting AES key.
c3_prime = 1
decrypted3 = helpers.rsa_decrypt(c3_prime, priv3)
alice_key3 = helpers.derive_aes_key(decrypted3)
mallory_key3 = helpers.derive_aes_key(1)
message3 = b"Hi Bob!"
ciphertext3 = helpers.aes_cbc_encrypt(alice_key3, message3)
recovered3 = helpers.aes_cbc_decrypt(mallory_key3, ciphertext3)

print()
print("//////////rsa key-fixing via malleability/////////")
print("e =", e3)
print("n =", n3)
print("Bob's original encrypted secret c =", c3)
print("Mallory's substituted c_prime =", c3_prime)
print("Alice decrypts c_prime to s =", decrypted3)
print("Mallory decrypts Alice's AES-CBC ciphertext to:", recovered3)

if recovered3 == message3:
    print("MATCH: Mallory fixes Alice's secret to 1 and decrypts her message without knowing the original secret")
else:
    print("MISMATCH: key-fixing attack did not recover the message")

assert decrypted3 == 1
assert recovered3 == message3