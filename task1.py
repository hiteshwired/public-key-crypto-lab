import helpers

q = 37
g = 5

# alice and bob each generate a private exponent
xa = helpers.dh_generate_private(q)
xb = helpers.dh_generate_private(q)

# each computes their public value from the shared q, g
ya = helpers.dh_public_value(g, xa, q)
yb = helpers.dh_public_value(g, xb, q)

# each computes the shared secret using the other party's public value
alice_shared_secret = helpers.dh_shared_secret(yb, xa, q)
bob_shared_secret = helpers.dh_shared_secret(ya, xb, q)

print("DH exchange")
print("q =", q)
print("g =", g)
print("Alice's private exponent (XA) =", xa)
print("Bob's private exponent (XB) =", xb)
print("Alice's public value (YA) =", ya)
print("Bob's public value (YB) =", yb)
print("Alice's computed shared secret =", alice_shared_secret)
print("Bob's computed shared secret =", bob_shared_secret)

#match check
if alice_shared_secret == bob_shared_secret:
    print("MATCH: Alice and Bob agree on the shared secret")
else:
    print("MISMATCH: shared secrets do not agree")

assert alice_shared_secret == bob_shared_secret

# derive an AES-128 key and exchange encrypted messages using the small parameters
small_aes_key = helpers.derive_aes_key(alice_shared_secret)
small_c0 = helpers.aes_cbc_encrypt(small_aes_key, b"Hi Bob!")
small_c1 = helpers.aes_cbc_encrypt(small_aes_key, b"Hi Alice!")
small_m0 = helpers.aes_cbc_decrypt(small_aes_key, small_c0)
small_m1 = helpers.aes_cbc_decrypt(small_aes_key, small_c1)

print("Small-parameter AES-CBC message exchange")
print("Alice sends:", small_m0)
print("Bob sends:", small_m1)
assert small_m0 == b"Hi Bob!"
assert small_m1 == b"Hi Alice!"

real_q, real_g = helpers.dh_real_params()

# alice and bob each generate a private exponent using the real modulus
real_xa = helpers.dh_generate_private(real_q)
real_xb = helpers.dh_generate_private(real_q)

# each computes their public value from the shared real q, g
real_ya = helpers.dh_public_value(real_g, real_xa, real_q)
real_yb = helpers.dh_public_value(real_g, real_xb, real_q)

# each computes the shared secret using the other party's public value
real_alice_shared_secret = helpers.dh_shared_secret(real_yb, real_xa, real_q)
real_bob_shared_secret = helpers.dh_shared_secret(real_ya, real_xb, real_q)

print("/////////real-parameter (IETF 1024-bit) DH exchange////////")
print("DH_1024_Q_HEX =", helpers.DH_1024_Q_HEX)
print("q =", real_q)
print("g =", real_g)
print("Alice's private exponent (XA) =", real_xa)
print("Bob's private exponent (XB) =", real_xb)
print("Alice's public value (YA) =", real_ya)
print("Bob's public value (YB) =", real_yb)
print("Alice's computed shared secret =", real_alice_shared_secret)
print("Bob's computed shared secret =", real_bob_shared_secret)

# explicit match check
if real_alice_shared_secret == real_bob_shared_secret:
    print("MATCH: Alice and Bob agree on the shared secret")
else:
    print("MISMATCH: shared secrets do not agree")

assert real_alice_shared_secret == real_bob_shared_secret

# derive a 16-byte AES-128 key from the real-parameter shared secret via SHA-256 truncation
aes_key = helpers.derive_aes_key(real_alice_shared_secret)

print("AES-128 key derivation from real-parameter shared secret")
print("Derived 16-byte AES-128 key (hex) =", aes_key.hex())
print("This key came from hashing the shared secret with SHA-256 and truncating to 16 bytes")

# exchange encrypted messages using the real parameters
c0 = helpers.aes_cbc_encrypt(aes_key, b"Hi Bob!")
c1 = helpers.aes_cbc_encrypt(aes_key, b"Hi Alice!")
m0 = helpers.aes_cbc_decrypt(aes_key, c0)
m1 = helpers.aes_cbc_decrypt(aes_key, c1)

print("Real-parameter AES-CBC message exchange")
print("Alice sends:", m0)
print("Bob sends:", m1)
assert m0 == b"Hi Bob!"
assert m1 == b"Hi Alice!"