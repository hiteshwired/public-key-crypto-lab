# Design Document

## Overview

This lab is implemented as four plain Python 3 files sitting side by side in the project folder: a shared `helpers.py` module and three runnable scripts `task1.py`, `task2.py`, `task3.py`. Each task script imports whatever it needs from `helpers.py` and then runs its demonstrations top to bottom with `print()` statements showing intermediate values, so the grader can just run `python task1.py`, `python task2.py`, `python task3.py` and read the output.

Style constraints carried over from the clarify phase:
- Only `#` line comments, no docstrings.
- PyCryptodome (`Crypto.Cipher.AES`, `Crypto.Hash.SHA256`, `Crypto.Util.number.getPrime`) for AES-CBC, hashing, and prime generation.
- RSA's modular inverse is computed with a hand-rolled extended Euclidean algorithm, not `Crypto.Util.number.inverse` or Python's `pow(x, -1, n)`.
- Exact IETF 1024-bit MODP hex constants for `q` and `g` in the real-parameter DH demo.

### Note on fidelity to professor's hints

The toy Diffie-Hellman parameters (`q = 37`, `g = 5`) and the recursive `egcd`/`mod_inverse` structure used in `helpers.py` are taken directly from the professor's posted assignment hints, per Requirement 9. They are used verbatim rather than replaced with different toy values or a differently-shaped extended Euclidean algorithm, so the implementation stays traceable to the posted hints.

## Architecture

```
Module3Assignment/
  helpers.py     # shared crypto primitives used by all three tasks
  task1.py       # Diffie-Hellman: toy params + real 1024-bit MODP params
  task2.py       # MITM key-fixing attack, generator-tampering attack
  task3.py       # textbook RSA keygen/enc/dec, malleability key-exchange attack, signature forgery
```

Data flows one direction: `helpers.py` has no dependency on the task scripts. Each task script calls into `helpers.py` for anything reusable (modexp-based DH, egcd / mod_inverse, RSA keygen/encrypt/decrypt/sign/verify, AES-CBC wrappers, SHA-256 key derivation) and keeps the attack-specific orchestration (interception, tampering, forging) local to itself since that logic is unique to each task and not reused elsewhere.

## Components and Interfaces

### helpers.py

```python
# --- extended euclidean / modular inverse (hand rolled, used for RSA) ---
# follows the professor's posted mod_inverse pseudocode exactly (Requirement 9)
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

# --- diffie-hellman ---
def dh_generate_private(q):
    # picks a random exponent in [2, q-2]
    ...

def dh_public_value(g, x, q):
    # returns g^x mod q
    return pow(g, x, q)

def dh_shared_secret(peer_public, x, q):
    # returns peer_public^x mod q
    return pow(peer_public, x, q)

# IETF 1024-bit MODP group (RFC 2409 / RFC 3526, Second Oakley Group)
DH_1024_Q_HEX = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
DH_1024_G = 2

def dh_real_params():
    # converts the exact IETF hex constant to an integer, no truncation
    q = int(DH_1024_Q_HEX, 16)
    g = DH_1024_G
    return q, g

# --- key derivation ---
def derive_aes_key(shared_secret_int):
    # hashes the shared secret's byte representation with SHA-256, truncates digest to 16 bytes for an AES-128 key
    ...  # returns 16 bytes

# --- AES-CBC wrappers ---
def aes_cbc_encrypt(key, plaintext_bytes):
    # random IV, PKCS7 pad, returns iv + ciphertext
    ...

def aes_cbc_decrypt(key, iv_and_ciphertext):
    # splits iv, decrypts, unpads, returns plaintext bytes
    ...

# --- textbook rsa ---
def rsa_generate_keypair(bits=512, e=65537):
    # uses getPrime(bits) for p and q, computes n, phi
    # computes d = mod_inverse(e, phi) using the hand rolled egcd above
    # returns ((e, n), (d, n))
    ...

def rsa_encrypt(m, pub):
    e, n = pub
    return pow(m, e, n)

def rsa_decrypt(c, priv):
    d, n = priv
    return pow(c, d, n)

def rsa_sign(m, priv):
    d, n = priv
    return pow(m, d, n)

def rsa_verify(s, pub):
    e, n = pub
    return pow(s, e, n)
```

### task1.py

- Calls `helpers.dh_generate_private`, `dh_public_value`, `dh_shared_secret` with small toy `q`/`g` (`q = 37`, `g = 5`, per the professor's posted hint), prints `q`, `g`, both private exponents, both public values, both computed shared secrets, and an explicit `assert`/printed check that they match.
- Repeats the same flow using `helpers.dh_real_params()` for the IETF 1024-bit `q`/`g`, printing the hex constant used and the resulting shared secret (as a large integer, likely truncated in display only, not in computation).
- Derives an AES key from the shared secret with `helpers.derive_aes_key` and prints it (hex) so Task 2 demos can reuse the same pattern.

### task2.py

**Key-fixing MITM demo**
- Sets up Alice and Bob's DH private exponents and toy/real `q`/`g` (reuses `helpers` functions).
- Computes `YA` and `YB` normally, then simulates Mallory intercepting: instead of forwarding the real `YA`/`YB`, Mallory substitutes `q` for both.
- Alice computes her "shared secret" as `pow(q, XA, q)` (using the tampered value in place of Bob's public value) and Bob does the symmetric thing; both land on `0`.
- Mallory, without ever knowing `XA` or `XB`, derives the same AES key from `shared_secret = 0` and demonstrates decrypting an AES-CBC message Alice encrypts for Bob.

**Generator-tampering demo**
- Runs three passes over the same `q`, swapping `g` for `1`, `q`, and `q - 1`.
- For each pass, computes `YA`, `YB`, and the shared secret with random private exponents, prints the result, and prints a one-line explanation of why the result is attacker-predictable (alpha=1 always gives 1; alpha=q always gives 0; alpha=q-1 gives 1 or q-1 depending on exponent parity).

### task3.py

- **Keygen/encrypt/decrypt**: calls `helpers.rsa_generate_keypair()`, picks a plaintext integer `m < n`, encrypts and decrypts it, prints all values and confirms the round trip.
- **Malleability key-exchange attack**:
  - r-multiplication variant: picks blinding factor `r`, computes `c_prime = (c * pow(r, e, n)) % n`, decrypts `c_prime` with the real private key, shows the result equals `(m * r) % n`.
  - direct-target variant: picks a target value `t`, computes `r = (t * helpers.mod_inverse(m, n)) % n`, computes `c_prime = (c * pow(r, e, n)) % n`, decrypts it, shows the result equals `t` exactly.
- **Signature forgery**: signs two messages `m1`, `m2` with `helpers.rsa_sign`, computes `s3 = (s1 * s2) % n` without touching the private key, computes `m3 = (m1 * m2) % n`, and verifies `helpers.rsa_verify(s3, pub) == m3`.
- Each demo ends with a printed explanation string tying the math back to the security implication (as required by Requirements 5.5 and 6.4); these are not independently tested since they're prose, not computed values.

## Data Models

No persistent data models are needed; this is a script-based demo. The relevant in-memory shapes are plain tuples/ints:
- DH keypair: `(private_exponent: int, public_value: int)`
- DH domain params: `(q: int, g: int)`
- RSA public key: `(e: int, n: int)`
- RSA private key: `(d: int, n: int)`
- AES key: `bytes` (16 bytes for AES-128)
- AES ciphertext: `bytes` formatted as `iv (16 bytes) + ciphertext`

## Error Handling

- `helpers.mod_inverse(a, m)` raises an `Exception` ("Modular inverse does not exist") if `gcd(a, m) != 1` (used both for RSA keygen, where `e`/`phi` are chosen/checked to be coprime, and for the direct-target malleability variant, where `m` must be coprime to `n`; since `n = p*q` for random large primes and `m` is a small demo integer, callers pick `m` to avoid the degenerate non-invertible case, or catch and retry with a different `m`).
- `dh_generate_private(q)` restricts the exponent range to `[2, q-2]` so a private exponent of `0` or `1` (which would make the demo trivial/degenerate) is never generated for the toy or real parameter demos.
- AES-CBC decryption in the MITM demo is expected to succeed (Mallory's derived key is correct by construction); no error handling is needed there beyond what PyCryptodome raises on padding failure, which would only occur if the design were wrong.

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Diffie-Hellman shared secret agreement

For any prime modulus q, generator g, and private exponents XA, XB in [2, q-2], computing YA = g^XA mod q and YB = g^XB mod q, then Bob's view (YA^XB mod q) and Alice's view (YB^XA mod q) SHALL be equal.

**Validates: Requirements 1.1, 1.2, 1.4**

### Property 2: AES key derivation is deterministic

For any integer shared secret value, deriving an AES key from it twice (via SHA-256) SHALL produce the identical key both times, and the derived key SHALL always be a valid AES key length (16 bytes for AES-128).

**Validates: Requirements 1.5**

### Property 3: Tampering the DH base value with q forces a zero shared secret

For any prime modulus q and any private exponent x in [1, q-1], computing q^x mod q SHALL equal 0, regardless of the value of x.

**Validates: Requirements 2.3, 3.3**

### Property 4: MITM-derived key matches and decrypts real traffic

For any plaintext message and any AES key derived from a shared secret of 0, encrypting the message with that key and then decrypting the resulting ciphertext with an independently-derived key from the same shared secret value SHALL recover the original plaintext exactly.

**Validates: Requirements 2.4, 2.5**

### Property 5: Generator alpha=1 forces a constant shared secret

For any prime modulus q and any private exponent x in [1, q-1], computing 1^x mod q SHALL equal 1, regardless of the value of x.

**Validates: Requirements 3.2**

### Property 6: Generator alpha=q-1 restricts the shared secret to two values by exponent parity

For any prime modulus q and any private exponent x in [1, q-1], computing (q-1)^x mod q SHALL equal 1 when x is even and SHALL equal (q-1) when x is odd.

**Validates: Requirements 3.4**

### Property 7: RSA modular inverse correctness

For any two positive integers a and m that are coprime, the hand-rolled recursive egcd-based mod_inverse function SHALL return an integer d such that (a * d) mod m == 1.

**Validates: Requirements 4.1, 4.4**

### Property 8: RSA encrypt/decrypt round trip

For any valid RSA keypair (generated via rsa_generate_keypair) and any plaintext integer m in [0, n), decrypting the encryption of m SHALL return m exactly.

**Validates: Requirements 4.2, 4.3**

### Property 9: RSA malleability via blinding factor multiplication

For any valid RSA keypair, any plaintext integer m in [0, n), and any blinding factor r in [2, n-1], computing c = encrypt(m), c' = (c * r^e) mod n, and decrypting c' SHALL yield (m * r) mod n.

**Validates: Requirements 5.2, 5.4**

### Property 10: RSA malleability to an attacker-chosen target value

For any valid RSA keypair, any plaintext integer m in [1, n-1] coprime to n, and any target value t in [0, n), computing c = encrypt(m), r = (t * mod_inverse(m, n)) mod n, c' = (c * r^e) mod n, and decrypting c' SHALL yield exactly t.

**Validates: Requirements 5.3, 5.4**

### Property 11: RSA signature forgery via multiplicative combination

For any valid RSA keypair and any two messages m1, m2 in [0, n), signing m1 and m2 to get s1 and s2, then computing s3 = (s1 * s2) mod n and m3 = (m1 * m2) mod n, verifying s3 (raising to e mod n) SHALL yield exactly m3, without s3 ever being computed using the private key directly.

**Validates: Requirements 6.1, 6.2, 6.3**

### Property 12: IETF 1024-bit MODP constants convert exactly

The integer produced by converting the published IETF 1024-bit MODP group hex string via int(hex_string, 16) SHALL equal the known reference integer value for that group, and the generator SHALL equal the published reference value (2), with no digits altered or truncated.

**Validates: Requirements 8.1, 8.2, 8.3**

## Testing Strategy

**Property tests** (100+ iterations each, using randomized inputs per the ranges stated above):
- Properties 1, 3, 5, 6 use randomized small primes q (a handful of known small primes, e.g. 11, 23, 47) and randomized exponents/generators to exercise the DH math in `helpers.py` directly, independent of which task script calls it.
- Property 2 uses randomized large integers as the "shared secret" input to `derive_aes_key`.
- Property 4 uses randomized plaintext byte strings against the AES-CBC wrappers with a fixed key derived from shared secret 0.
- Property 7 uses randomized coprime integer pairs (generated by picking a and a random m, ensuring gcd(a,m)==1) against `helpers.mod_inverse`.
- Properties 8, 9, 10 use a small number of freshly generated RSA keypairs (small bit sizes, e.g. 256-512 bits, to keep iteration cost low) crossed with randomized plaintext/blinding/target values.
- Property 11 uses a small number of freshly generated RSA keypairs crossed with randomized message pairs.
- Property 12 is effectively a single fixed-value check (the hex constant is fixed), so it is implemented as a unit/example test, not a randomized property test, even though it's listed here for traceability.

**Unit/example tests** (specific, non-randomized):
- Toy-parameter DH exchange in task1.py produces matching secrets for one fixed (q, g, XA, XB) example.
- IETF hex constant matches the exact published reference value (Property 12, implemented as an example test).
- RSA keygen produces n = p*q and phi = (p-1)*(q-1) for one generated keypair, sanity-checking the setup before the round-trip property takes over.
- Generator-tampering demo prints the expected explanatory text for each of the three alpha cases (smoke-level check that all three cases run without error).

Property tests target `helpers.py` functions directly (they are pure functions of their inputs), which keeps iteration cost low and avoids coupling tests to the print-heavy orchestration in the task scripts. The task scripts themselves are covered by lightweight smoke/example tests confirming they run end-to-end without raising exceptions and produce the expected printed assertions.
