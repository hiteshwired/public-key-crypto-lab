# Requirements Document

## Introduction

This feature implements a set of Python scripts for a CSC-3201 assignment on public-key cryptography. The lab has three parts: (1) a demonstration of the Diffie-Hellman key exchange using both small toy parameters and real 1024-bit MODP parameters from IETF RFC 3526/2409-style groups, (2) an implementation and demonstration of man-in-the-middle attacks against unauthenticated Diffie-Hellman (key-fixing via YA/YB substitution, and generator tampering with alpha = 1, q, and q-1), and (3) a textbook RSA implementation along with demonstrations of RSA malleability attacks against a naive key-exchange protocol and an RSA signature forgery attack exploiting multiplicative malleability.

The code is written in a student-natural style: plain Python 3 scripts, `#` comments only (no docstrings), using PyCryptodome for AES-CBC, SHA-256, and prime generation, but a hand-rolled extended Euclidean algorithm for RSA modular inverses (not a library call). Shared logic lives in a helpers module imported by three per-task scripts (task1.py, task2.py, task3.py).

## Requirements

### Requirement 1: Diffie-Hellman key exchange demonstration

**User Story:** As a student, I want to run a Diffie-Hellman key exchange using both small toy numbers and real IETF-standard 1024-bit MODP parameters, so that I can observe and verify that both parties independently compute the same shared secret.

#### Acceptance Criteria

1. WHEN task1.py is run THEN the system SHALL perform the toy Diffie-Hellman exchange using q = 37 and g = 5 as the small toy parameters and print q, g, the private exponents, the public values YA/YB, and the resulting shared secret for both parties.
2. WHEN task1.py performs the toy Diffie-Hellman exchange THEN the system SHALL generate a private key for Alice and a private key for Bob.
3. WHEN task1.py computes the public values for the toy exchange THEN the system SHALL compute each party's public key via modular exponentiation using pow() (YA = pow(g, XA, q) and YB = pow(g, XB, q)).
4. WHEN task1.py computes the shared secret from each party's perspective THEN the system SHALL compute the shared secret for both Alice and Bob and verify both computations produce an identical shared secret value, reporting the match explicitly.
5. WHEN either the toy exchange or the real-parameter exchange completes THEN the system SHALL derive a symmetric key from the shared secret by hashing the shared secret with SHA-256 and truncating the digest to 16 bytes, producing a 16-byte AES-128 key.
6. WHEN task1.py encrypts a message with the derived 16-byte key THEN the system SHALL implement AES-CBC encryption using a random IV generated per message and SHALL apply padding to the plaintext before encryption.
7. WHEN task1.py decrypts a message with the derived 16-byte key THEN the system SHALL implement AES-CBC decryption and SHALL remove the padding from the decrypted plaintext.
8. WHEN task1.py simulates the full protocol THEN the system SHALL generate private/public keys for Alice and Bob, compute the shared secrets for both parties, derive the 16-byte symmetric key for each party from its shared secret, and encrypt/decrypt test messages exchanged between Alice and Bob.
9. WHEN the full protocol simulation completes THEN the system SHALL verify that the test messages exchanged between Alice and Bob decrypt successfully and SHALL verify that Alice and Bob derive the same symmetric key.
10. WHEN task1.py runs the real-parameter exchange THEN the system SHALL use the exact IETF 1024-bit MODP group q (prime modulus) and g (generator) hex values as specified in the RFC, converted to integers.
11. WHEN task1.py performs the real-parameter exchange THEN the system SHALL generate random private exponents for each party, compute public values YA = g^XA mod q and YB = g^XB mod q, and compute the shared secret K = YB^XA mod q = YA^XB mod q.

### Requirement 2: Man-in-the-middle key-fixing attack on Diffie-Hellman

**User Story:** As a student, I want to demonstrate a MITM attack where Mallory intercepts and replaces YA and YB with the prime modulus q, so that I can show the shared secret becomes fixed to 0 and both legitimate parties unknowingly share a key known to the attacker.

#### Acceptance Criteria

1. WHEN task2.py runs the key-fixing MITM demonstration THEN the system SHALL simulate Alice and Bob performing Diffie-Hellman while Mallory intercepts the exchange.
2. WHEN Mallory intercepts YA and YB THEN the system SHALL replace both transmitted values with q (the prime modulus) before forwarding them to the other party.
3. WHEN Alice and Bob each compute their shared secret using the tampered value (q) in place of the peer's public value THEN the system SHALL show that both independently compute a shared secret of 0 mod q.
4. WHEN the shared secret is fixed to 0 THEN the system SHALL demonstrate that Mallory, knowing the shared secret is 0 without needing either private exponent, can derive the same symmetric key and decrypt/encrypt AES-CBC traffic exchanged between Alice and Bob.
5. WHEN task2.py demonstrates the attack impact THEN the system SHALL encrypt a plaintext message with the derived key using AES-CBC and show Mallory successfully decrypting it.

### Requirement 3: Generator tampering attack on Diffie-Hellman

**User Story:** As a student, I want to demonstrate how a malicious or corrupted generator value (alpha = 1, alpha = q, or alpha = q-1) forces the shared secret into a small, predictable set of values, so that I can show why generator/domain-parameter validation matters.

#### Acceptance Criteria

1. WHEN task2.py runs the generator-tampering demonstration THEN the system SHALL run the Diffie-Hellman exchange three times, substituting the generator g with alpha = 1, alpha = q, and alpha = q - 1 respectively, while keeping q fixed.
2. WHEN alpha = 1 is used as the generator THEN the system SHALL show that all public values (YA, YB) and the resulting shared secret equal 1, regardless of the private exponents chosen.
3. WHEN alpha = q is used as the generator THEN the system SHALL show that all public values and the resulting shared secret equal 0 mod q, regardless of the private exponents chosen.
4. WHEN alpha = q - 1 is used as the generator THEN the system SHALL show that the resulting shared secret is restricted to only two possible values (1 or q-1), determined by the parity (even/odd) of the private exponents, and the demonstration SHALL print which of the two values results.
5. WHEN each tampered-generator case completes THEN the system SHALL state in output why the resulting shared secret is trivially guessable by an attacker without knowledge of either private exponent.

### Requirement 4: Textbook RSA key generation, encryption, and decryption

**User Story:** As a student, I want a from-scratch textbook RSA implementation (no OAEP/PKCS padding), so that I can demonstrate RSA's raw mathematical behavior including its malleability weaknesses.

#### Acceptance Criteria

1. WHEN task3.py generates an RSA keypair THEN the system SHALL generate two large random primes p and q (via PyCryptodome's getPrime), compute n = p*q and phi = (p-1)*(q-1), select a public exponent e, and compute the private exponent d as the modular inverse of e mod phi using a hand-rolled mod_inverse function (not a library modinv call).
2. WHEN task3.py encrypts a message m (0 <= m < n) THEN the system SHALL compute ciphertext c = m^e mod n using textbook (unpadded) RSA.
3. WHEN task3.py decrypts a ciphertext c THEN the system SHALL compute m = c^d mod n and the recovered value SHALL equal the original plaintext integer for any valid message in range.
4. WHEN the mod_inverse function computes the modular inverse of a value a mod m THEN the system SHALL implement it as a recursive egcd(a, b) helper following this exact structure: the base case (a == 0) SHALL return (b, 0, 1); the recursive case SHALL compute g, y, x = egcd(b % a, a) and SHALL return (g, x - (b // a) * y, y); mod_inverse SHALL call g, x, _ = egcd(a, m), SHALL raise an exception when g != 1 (modular inverse does not exist), and SHALL otherwise return x % m.
5. WHEN the mod_inverse function returns a value d for inputs a and m THEN the system SHALL ensure d satisfies (a * d) mod m == 1.

### Requirement 5: RSA malleability attack on a key-exchange protocol

**User Story:** As a student, I want to demonstrate that textbook RSA's multiplicative malleability lets an attacker manipulate an encrypted key-exchange value without knowing the private key, so that I can show both a blinding-factor (r-multiplication) variant and a direct-target-value variant of the attack.

#### Acceptance Criteria

1. WHEN task3.py sets up the RSA key-exchange malleability demonstration THEN the system SHALL encrypt a secret key-exchange value m under the victim's RSA public key to produce ciphertext c.
2. WHEN performing the r-multiplication variant of the attack THEN the system SHALL choose an attacker-known blinding factor r, compute c' = c * r^e mod n, and show that decrypting c' yields m' = m * r mod n (i.e., the decrypted value is the original value scaled by the attacker-chosen r), without the attacker ever learning d.
3. WHEN performing the direct-target-value variant of the attack THEN the system SHALL choose an attacker-desired target plaintext value t, compute the multiplier r = t * m^-1 mod n (using the hand-rolled extended Euclidean algorithm for the modular inverse of m), compute c' = c * r^e mod n, and show that decrypting c' yields exactly t.
4. WHEN either malleability variant completes THEN the system SHALL verify the claimed relationship holds by decrypting the tampered ciphertext with the real private key and comparing against the expected value (m*r mod n, or t, respectively).
5. WHEN task3.py demonstrates attack impact THEN the system SHALL explain (via printed output) how this malleability could let an attacker manipulate a key-exchange value even without breaking RSA or learning the private key.

### Requirement 6: RSA signature malleability forgery attack

**User Story:** As a student, I want to demonstrate that RSA's multiplicative property also allows forging a valid signature on a new message by combining two known valid signatures, so that I can show why raw RSA signing without proper padding/hashing is unsafe.

#### Acceptance Criteria

1. WHEN task3.py sets up the signature forgery demonstration THEN the system SHALL use textbook RSA signing (s = m^d mod n) to produce valid signatures for two chosen messages m1 and m2 using the signer's private key.
2. WHEN the attacker only has access to the signatures s1 (for m1) and s2 (for m2) and the public key THEN the system SHALL forge a signature for the target message m3 = (m1 * m2) mod n by computing s3 = (s1 * s2) mod n, without ever using the private key.
3. WHEN the forged signature s3 is verified THEN the system SHALL show that s3^e mod n == m3, i.e., the forged signature verifies as valid for m3 under the signer's public key.
4. WHEN the forgery demonstration completes THEN the system SHALL explain (via printed output) why this multiplicative relationship between messages and signatures breaks unforgeability for raw/textbook RSA signatures.

### Requirement 7: Shared helper module and script organization

**User Story:** As a student, I want common cryptographic helper functions factored into a shared module, so that task1.py, task2.py, and task3.py stay focused on demonstrating each attack/protocol without duplicating logic.

#### Acceptance Criteria

1. WHEN the project is organized THEN the system SHALL place reusable functions (modular exponentiation helpers if needed, extended Euclidean algorithm / modular inverse, AES-CBC encrypt/decrypt wrappers, SHA-256 key derivation, DH keypair/shared-secret computation, RSA keygen/encrypt/decrypt/sign/verify) into a single shared helpers module.
2. WHEN task1.py, task2.py, or task3.py need shared functionality THEN the system SHALL import it from the shared helpers module rather than redefining it locally.
3. WHEN any of the three task scripts is run directly THEN the system SHALL execute only the demonstrations relevant to that task (Task 1: DH demos; Task 2: MITM key-fixing and generator-tampering demos; Task 3: RSA keygen/encrypt/decrypt, RSA malleability key-exchange attack, RSA signature forgery).
4. WHEN code is written across the helpers module and task scripts THEN the system SHALL use only `#` line comments (no docstrings/triple-quoted comments) and plain, student-natural Python style.
5. WHEN cryptographic primitives are needed THEN the system SHALL use PyCryptodome for AES-CBC, SHA-256, and prime generation (getPrime), and SHALL use a hand-rolled extended Euclidean algorithm (not a library function) for RSA modular inverse computation.

### Requirement 8: IETF 1024-bit MODP parameters

**User Story:** As a student, I want the real Diffie-Hellman demonstration to use the exact, standard 1024-bit MODP prime and generator, so that the exchange reflects real-world parameter sizes rather than toy values.

#### Acceptance Criteria

1. WHEN task1.py or the shared helpers module defines the real DH parameters THEN the system SHALL encode the IETF 1024-bit MODP group prime (q) as its exact published hex string, converted to an integer via `int(hex_string, 16)`.
2. WHEN task1.py or the shared helpers module defines the real DH parameters THEN the system SHALL use the exact published generator (g) value for that group (as an integer, e.g. 2), matching the IETF specification exactly.
3. WHEN the real-parameter exchange runs THEN the system SHALL NOT alter or truncate the standard hex digits when converting to integers.

### Requirement 9: Fidelity to professor-provided hints and instructions

**User Story:** As a student, I want my code to visibly build on the hints and instructions the professor posted for this assignment, so that my submission authentically reflects a student using the professor's own guidance as a starting point and reference rather than substituting a generic or idiomatic alternative.

#### Acceptance Criteria

1. WHERE the professor has posted a toy Diffie-Hellman parameter hint, THE system SHALL use the professor-specified values (q = 37, g = 5) exactly as given rather than a different or arbitrarily chosen toy modulus and generator.
2. WHERE the professor has posted a mod_inverse pseudocode hint, THE system SHALL implement the RSA modular inverse function following the exact recursive egcd structure given in the hint (base case a == 0 returns (b, 0, 1); recursive case computes g, y, x = egcd(b % a, a) and returns g, x - (b // a) * y, y) rather than a generic iterative or differently-ordered extended Euclidean algorithm.
3. WHEN the professor's posted hints specify a structural or procedural detail (parameter values, function shape, algorithm steps) THE system SHALL follow that detail as closely as reasonably possible in the corresponding implementation rather than replacing it with an idiomatic or generic alternative.
4. WHEN code is written to satisfy Requirements 1 and 4 THE system SHALL reflect the professor's hints closely enough that a grader reviewing the submission alongside the posted hints can recognize the code as having been built from those hints.
