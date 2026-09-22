import helpers

q = 37
g = 5

print("Key-Fixing MITM Demo")
print("q =", q)
print("g =", g)

# alice and bob each generate their own private exponent
XA = helpers.dh_generate_private(q)
XB = helpers.dh_generate_private(q)

print("Alice's private exponent XA =", XA)
print("Bob's private exponent XB =", XB)

# alice and bob compute their real public values to send to each other
YA = helpers.dh_public_value(g, XA, q)
YB = helpers.dh_public_value(g, XB, q)

print("Alice's real public value YA =", YA)
print("Bob's real public value YB =", YB)

# mallory sits in the middle and intercepts both YA and YB before they arrive
print()
print("Mallory intercepts the exchange...")
print("Mallory sees Alice's real YA =", YA, "in transit to Bob")
print("Mallory sees Bob's real YB =", YB, "in transit to Alice")

# instead of forwarding the real values, mallory substitutes q for both
tampered_value = q
print("Mallory substitutes q =", tampered_value, "in place of YA and YB")
print("Mallory forwards", tampered_value, "to Bob instead of Alice's real YA")
print("Mallory forwards", tampered_value, "to Alice instead of Bob's real YB")

# instead of using each other's real public value, they both got q from mallory
print()
print("Alice and Bob each compute their shared secret using the tampered value...")

# alice thinks she's computing YB^XA mod q, but YB was replaced with q
alice_shared_secret = helpers.dh_shared_secret(tampered_value, XA, q)

# bob thinks he's computing YA^XB mod q, but YA was replaced with q
bob_shared_secret = helpers.dh_shared_secret(tampered_value, XB, q)

print("Alice computes shared secret =", alice_shared_secret)
print("Bob computes shared secret =", bob_shared_secret)

# both land on 0 mod q, no matter what XA and XB are
assert alice_shared_secret == 0
assert bob_shared_secret == 0
print("Confirmed: both Alice and Bob independently arrive at a shared secret of 0 mod q")

# mallory never learned XA or XB, but she doesn't need to: she already knows the tampering forces the shared secret to 0, so she can derive the same AES key alice and bob end up using
print()
print("Mallory derives the same AES key from the known shared secret of 0...")

alice_key = helpers.derive_aes_key(alice_shared_secret)
mallory_key = helpers.derive_aes_key(0)

message = b"Hi Bob!"
reply = b"Hi Alice!"
ciphertext = helpers.aes_cbc_encrypt(alice_key, message)
reply_ciphertext = helpers.aes_cbc_encrypt(alice_key, reply)
decrypted = helpers.aes_cbc_decrypt(mallory_key, ciphertext)
decrypted_reply = helpers.aes_cbc_decrypt(mallory_key, reply_ciphertext)

print("Original message Alice sends to Bob:", message)
print("Original message Bob sends to Alice:", reply)
print("Mallory's derived AES key (hex):", mallory_key.hex())
print("Ciphertext Alice sends (iv + ciphertext, hex):", ciphertext.hex())
print("Mallory decrypts the ciphertext to:", decrypted)
print("Mallory decrypts Bob's ciphertext to:", decrypted_reply)

assert decrypted == message
assert decrypted_reply == reply
print("MATCH: Mallory successfully decrypted Alice's message without ever knowing XA or XB")


print()
print("Generator-Tampering Demo")
print("q =", q)

alpha = 1
print()
print("Pass 1: alpha =", alpha)

XA1 = helpers.dh_generate_private(q)
XB1 = helpers.dh_generate_private(q)

YA1 = helpers.dh_public_value(alpha, XA1, q)
YB1 = helpers.dh_public_value(alpha, XB1, q)

shared1 = helpers.dh_shared_secret(YB1, XA1, q)

print("XA =", XA1, " XB =", XB1)
print("YA =", YA1, " YB =", YB1)
print("Shared secret =", shared1)
print("with alpha = 1, 1^x mod q is always 1 no matter what x is,")

key1 = helpers.derive_aes_key(1)
c01 = helpers.aes_cbc_encrypt(helpers.derive_aes_key(shared1), b"Hi Bob!")
c11 = helpers.aes_cbc_encrypt(helpers.derive_aes_key(shared1), b"Hi Alice!")
print("Mallory decrypts m0:", helpers.aes_cbc_decrypt(key1, c01))
print("Mallory decrypts m1:", helpers.aes_cbc_decrypt(key1, c11))

alpha = q
print()
print("Pass 2: alpha =", alpha)

XA2 = helpers.dh_generate_private(q)
XB2 = helpers.dh_generate_private(q)

YA2 = helpers.dh_public_value(alpha, XA2, q)
YB2 = helpers.dh_public_value(alpha, XB2, q)

shared2 = helpers.dh_shared_secret(YB2, XA2, q)

print("XA =", XA2, " XB =", XB2)
print("YA =", YA2, " YB =", YB2)
print("Shared secret =", shared2)

key2 = helpers.derive_aes_key(0)
c02 = helpers.aes_cbc_encrypt(helpers.derive_aes_key(shared2), b"Hi Bob!")
c12 = helpers.aes_cbc_encrypt(helpers.derive_aes_key(shared2), b"Hi Alice!")
print("Mallory decrypts m0:", helpers.aes_cbc_decrypt(key2, c02))
print("Mallory decrypts m1:", helpers.aes_cbc_decrypt(key2, c12))


alpha = q - 1
print()
print("Pass 3: alpha =", alpha)

XA3 = helpers.dh_generate_private(q)
XB3 = helpers.dh_generate_private(q)

YA3 = helpers.dh_public_value(alpha, XA3, q)
YB3 = helpers.dh_public_value(alpha, XB3, q)

shared3 = helpers.dh_shared_secret(YB3, XA3, q)

print("XA =", XA3, " XB =", XB3)
print("YA =", YA3, " YB =", YB3)
print("Shared secret =", shared3)

# (q-1)^x mod q is 1 if x is even, or q-1 if x is odd, so the shared secret only ever lands on one of these two values
if shared3 == 1:
    print("Result: shared secret landed on 1 (even exponent case)")
else:
    print("Result: shared secret landed on", q - 1, "(odd exponent case)")

c03 = helpers.aes_cbc_encrypt(helpers.derive_aes_key(shared3), b"Hi Bob!")
c13 = helpers.aes_cbc_encrypt(helpers.derive_aes_key(shared3), b"Hi Alice!")
for candidate_secret in (1, q - 1):
    candidate_key = helpers.derive_aes_key(candidate_secret)
    try:
        recovered_m0 = helpers.aes_cbc_decrypt(candidate_key, c03)
        recovered_m1 = helpers.aes_cbc_decrypt(candidate_key, c13)
        print("Mallory tries shared secret", candidate_secret, "and recovers m0:", recovered_m0)
        print("Mallory tries shared secret", candidate_secret, "and recovers m1:", recovered_m1)
        break
    except ValueError:
        pass