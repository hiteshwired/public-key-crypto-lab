# test_helpers.py
# property based tests for helpers.py

import math
from hypothesis import given, settings, strategies as st

import helpers


# --- Property 7: RSA modular inverse correctness ---
# Validates: Requirements 4.1, 4.4
# for any two positive integers a and m that are coprime, mod_inverse(a, m)
# SHALL return an integer d such that (a * d) mod m == 1

@st.composite
def coprime_pairs(draw):
    # draw a modulus m >= 2, then draw a until it happens to be coprime with m
    m = draw(st.integers(min_value=2, max_value=10_000))
    a = draw(st.integers(min_value=1, max_value=10_000).filter(lambda v: math.gcd(v, m) == 1))
    return a, m


@given(coprime_pairs())
@settings(max_examples=100)
def test_mod_inverse_correctness(pair):
    a, m = pair
    d = helpers.mod_inverse(a, m)
    assert (a * d) % m == 1


# --- Property 1: Diffie-Hellman shared secret agreement ---
# Validates: Requirements 1.1, 1.2, 1.4
# for any prime modulus q, generator g, and private exponents XA, XB in [2, q-2],
# computing YA = g^XA mod q and YB = g^XB mod q, then Bob's view (YA^XB mod q)
# and Alice's view (YB^XA mod q) SHALL be equal

small_primes_q = st.sampled_from([11, 23, 37, 47])


@st.composite
def dh_params(draw):
    # pick one of the small known primes as q, then draw a generator and two
    # private exponents in the valid [2, q-2] range
    q = draw(small_primes_q)
    g = draw(st.integers(min_value=2, max_value=q - 2))
    xa = draw(st.integers(min_value=2, max_value=q - 2))
    xb = draw(st.integers(min_value=2, max_value=q - 2))
    return q, g, xa, xb


@given(dh_params())
@settings(max_examples=100)
def test_dh_shared_secret_agreement(params):
    q, g, xa, xb = params
    ya = helpers.dh_public_value(g, xa, q)
    yb = helpers.dh_public_value(g, xb, q)
    bobs_view = helpers.dh_shared_secret(ya, xb, q)
    alices_view = helpers.dh_shared_secret(yb, xa, q)
    assert bobs_view == alices_view


# --- Property 12: IETF 1024-bit MODP constants convert exactly ---
# Validates: Requirements 8.1, 8.2, 8.3
# the hex constant is fixed, so this is a unit/example test, not a randomized
# property test, per the design's testing strategy

REFERENCE_DH_1024_Q_HEX = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"


def test_dh_1024_hex_constant_matches_reference():
    assert helpers.DH_1024_Q_HEX == REFERENCE_DH_1024_Q_HEX


def test_dh_1024_generator_matches_reference():
    assert helpers.DH_1024_G == 2


def test_dh_real_params_converts_exactly():
    q, g = helpers.dh_real_params()
    assert q == int(REFERENCE_DH_1024_Q_HEX, 16)
    assert g == 2
    assert q.bit_length() == 2048


# --- Property 8: RSA encrypt/decrypt round trip ---
# Validates: Requirements 4.2, 4.3
# for any valid RSA keypair (generated via rsa_generate_keypair) and any
# plaintext integer m in [0, n), decrypting the encryption of m SHALL return m exactly

# generate a small handful of keypairs once, up front, using small bits so
# this stays fast, instead of generating a fresh keypair on every hypothesis example
rsa_test_keypairs = [helpers.rsa_generate_keypair(bits=256) for _ in range(3)]


@st.composite
def rsa_keypair_and_message(draw):
    # pick one of the pre-generated keypairs, then draw a random plaintext m in [0, n)
    pub, priv = draw(st.sampled_from(rsa_test_keypairs))
    n = pub[1]
    m = draw(st.integers(min_value=0, max_value=n - 1))
    return pub, priv, m


@given(rsa_keypair_and_message())
@settings(max_examples=100)
def test_rsa_encrypt_decrypt_round_trip(case):
    pub, priv, m = case
    c = helpers.rsa_encrypt(m, pub)
    recovered = helpers.rsa_decrypt(c, priv)
    assert recovered == m


# --- Property 2: AES key derivation is deterministic ---
# Validates: Requirements 1.5
# for any integer shared secret value, deriving an AES key from it twice
# (via SHA-256) SHALL produce the identical key both times, and the derived
# key SHALL always be a valid AES key length (16 bytes for AES-128)

@given(st.integers(min_value=0, max_value=2**2048))
@settings(max_examples=100)
def test_derive_aes_key_deterministic(shared_secret):
    key1 = helpers.derive_aes_key(shared_secret)
    key2 = helpers.derive_aes_key(shared_secret)
    assert key1 == key2
    assert len(key1) == 16


# --- Property 4: MITM-derived key matches and decrypts real traffic ---
# Validates: Requirements 2.4, 2.5
# for any plaintext message and any AES key derived from a shared secret of 0,
# encrypting the message with that key and then decrypting the resulting
# ciphertext with an independently-derived key from the same shared secret
# value SHALL recover the original plaintext exactly

@given(st.binary())
@settings(max_examples=100)
def test_mitm_derived_key_round_trip(plaintext):
    key1 = helpers.derive_aes_key(0)
    key2 = helpers.derive_aes_key(0)
    ciphertext = helpers.aes_cbc_encrypt(key1, plaintext)
    recovered = helpers.aes_cbc_decrypt(key2, ciphertext)
    assert recovered == plaintext


# --- toy-parameter DH exchange example test ---
# Validates: Requirements 1.1, 1.2
# q = 37, g = 5 are the professor's posted toy parameters, so this is a fixed
# unit/example test, not a randomized property test, per the design's testing strategy

def test_toy_dh_exchange_matches_secrets():
    q = 37
    g = 5
    xa = 6
    xb = 15
    ya = helpers.dh_public_value(g, xa, q)
    yb = helpers.dh_public_value(g, xb, q)
    bobs_view = helpers.dh_shared_secret(ya, xb, q)
    alices_view = helpers.dh_shared_secret(yb, xa, q)
    assert bobs_view == alices_view


# --- RSA keygen setup sanity check ---
# Validates: Requirements 4.1
# checks that a generated keypair actually comes from n = p*q and phi = (p-1)*(q-1),
# sanity-checking the keygen setup before the round-trip property takes over

def test_rsa_keygen_n_and_phi_match_primes():
    p, q, n, phi, d = helpers._rsa_generate_key_material(bits=256)
    assert n == p * q
    assert phi == (p - 1) * (q - 1)


# --- Property 3: Tampering the DH base value with q forces a zero shared secret ---
# Validates: Requirements 2.3, 3.3
# for any prime modulus q and any private exponent x in [1, q-1], computing
# q^x mod q SHALL equal 0, regardless of the value of x (models the tampered
# base value = q scenario from Mallory's key-fixing attack)

@st.composite
def q_and_exponent(draw):
    # pick one of the small known primes as q, then draw an exponent x in [1, q-1]
    q = draw(small_primes_q)
    x = draw(st.integers(min_value=1, max_value=q - 1))
    return q, x


@given(q_and_exponent())
@settings(max_examples=100)
def test_tampered_base_value_forces_zero_shared_secret(params):
    q, x = params
    assert helpers.dh_public_value(q, x, q) == 0


# --- Property 5: Generator alpha=1 forces a constant shared secret ---
# Validates: Requirements 3.2
# for any prime modulus q and any private exponent x in [1, q-1], computing
# 1^x mod q SHALL equal 1, regardless of the value of x

@st.composite
def alpha_one_params(draw):
    # pick one of the small known primes as q, then draw a private exponent in [1, q-1]
    q = draw(small_primes_q)
    x = draw(st.integers(min_value=1, max_value=q - 1))
    return q, x


@given(alpha_one_params())
@settings(max_examples=100)
def test_generator_alpha_one_constant_shared_secret(params):
    q, x = params
    assert helpers.dh_public_value(1, x, q) == 1


# --- Property 6: Generator alpha=q-1 restricts the shared secret to two values by exponent parity ---
# Validates: Requirements 3.4
# for any prime modulus q and any private exponent x in [1, q-1], computing
# (q-1)^x mod q SHALL equal 1 when x is even and SHALL equal (q-1) when x is odd

@st.composite
def alpha_q_minus_1_params(draw):
    # pick one of the small known primes as q, then draw a private exponent in [1, q-1]
    q = draw(small_primes_q)
    x = draw(st.integers(min_value=1, max_value=q - 1))
    return q, x


@given(alpha_q_minus_1_params())
@settings(max_examples=100)
def test_generator_alpha_q_minus_1_two_value_shared_secret(params):
    q, x = params
    result = helpers.dh_public_value(q - 1, x, q)
    if x % 2 == 0:
        assert result == 1
    else:
        assert result == q - 1


# --- Property 9: RSA malleability via blinding factor multiplication ---
# Validates: Requirements 5.2, 5.4
# for any valid RSA keypair, any plaintext integer m in [0, n), and any
# blinding factor r in [2, n-1], computing c = encrypt(m), c' = (c * r^e) mod n,
# and decrypting c' SHALL yield (m * r) mod n

@st.composite
def rsa_keypair_message_and_blind(draw):
    # reuse the pre-generated keypairs from the round-trip property test above,
    # then draw a plaintext m in [0, n) and a blinding factor r in [2, n-1]
    pub, priv = draw(st.sampled_from(rsa_test_keypairs))
    n = pub[1]
    m = draw(st.integers(min_value=0, max_value=n - 1))
    r = draw(st.integers(min_value=2, max_value=n - 1))
    return pub, priv, m, r


@given(rsa_keypair_message_and_blind())
@settings(max_examples=100)
def test_rsa_malleability_blinding_factor(case):
    pub, priv, m, r = case
    e, n = pub
    c = helpers.rsa_encrypt(m, pub)
    c_prime = (c * pow(r, e, n)) % n
    decrypted = helpers.rsa_decrypt(c_prime, priv)
    assert decrypted == (m * r) % n


# --- Property 11: RSA signature forgery via multiplicative combination ---
# Validates: Requirements 6.1, 6.2, 6.3
# for any valid RSA keypair and any two messages m1, m2 in [0, n), signing m1
# and m2 to get s1 and s2, then computing s3 = (s1 * s2) mod n and
# m3 = (m1 * m2) mod n, verifying s3 SHALL yield exactly m3, without s3 ever
# being computed using the private key directly

@st.composite
def rsa_keypair_and_message_pair(draw):
    # reuse the pre-generated keypairs from the round-trip property test above,
    # then draw two plaintext messages m1, m2 in [0, n)
    pub, priv = draw(st.sampled_from(rsa_test_keypairs))
    n = pub[1]
    m1 = draw(st.integers(min_value=0, max_value=n - 1))
    m2 = draw(st.integers(min_value=0, max_value=n - 1))
    return pub, priv, m1, m2


@given(rsa_keypair_and_message_pair())
@settings(max_examples=100)
def test_rsa_signature_forgery_multiplicative_combination(case):
    pub, priv, m1, m2 = case
    n = pub[1]
    s1 = helpers.rsa_sign(m1, priv)
    s2 = helpers.rsa_sign(m2, priv)
    s3 = (s1 * s2) % n
    m3 = (m1 * m2) % n
    verified = helpers.rsa_verify(s3, pub)
    assert verified == m3


# --- Property 10: RSA malleability to an attacker-chosen target value ---
# Validates: Requirements 5.3, 5.4
# for any valid RSA keypair, any plaintext integer m in [1, n-1] coprime to n,
# and any target value t in [0, n), computing c = encrypt(m),
# r = (t * mod_inverse(m, n)) mod n, c' = (c * r^e) mod n, and decrypting c'
# SHALL yield exactly t

@st.composite
def rsa_keypair_message_and_target(draw):
    # reuse the pre-generated keypairs from the round-trip property test above,
    # draw a plaintext m in [1, n-1] coprime with n (filtering is just a safety
    # net since n is a large semiprime, virtually every m will already be coprime),
    # then draw a target value t in [0, n-1]
    pub, priv = draw(st.sampled_from(rsa_test_keypairs))
    n = pub[1]
    m = draw(st.integers(min_value=1, max_value=n - 1).filter(lambda v: math.gcd(v, n) == 1))
    t = draw(st.integers(min_value=0, max_value=n - 1))
    return pub, priv, m, t


@given(rsa_keypair_message_and_target())
@settings(max_examples=100)
def test_rsa_malleability_attacker_chosen_target(case):
    pub, priv, m, t = case
    e, n = pub
    c = helpers.rsa_encrypt(m, pub)
    r = (t * helpers.mod_inverse(m, n)) % n
    c_prime = (c * pow(r, e, n)) % n
    decrypted = helpers.rsa_decrypt(c_prime, priv)
    assert decrypted == t
