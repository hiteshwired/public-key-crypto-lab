
# Implementation Plan: Public Key Crypto Lab

## Overview

Build one shared helpers module (`helpers.py`) and three runnable demo scripts (`task1.py`, `task2.py`, `task3.py`) in plain student-style Python 3, using `#` line comments only (no docstrings). PyCryptodome provides AES-CBC, SHA-256, and prime generation; RSA's modular inverse uses a hand-rolled recursive `egcd`/`mod_inverse` pair that follows the professor's posted pseudocode exactly (Requirement 9). Work proceeds bottom-up: shared primitives in `helpers.py` first (with property tests validating the math), then each task script layers its demo on top.

## Tasks

- [x] 1. Set up project files and modular inverse primitive
  - Create `helpers.py` with `egcd(a, b)` and `mod_inverse(a, m)` as specified in the design: `egcd` base case `a == 0` returns `(b, 0, 1)`; recursive case computes `g, y, x = egcd(b % a, a)` and returns `(g, x - (b // a) * y, y)`; `mod_inverse` calls `g, x, _ = egcd(a, m)`, raises an `Exception` when `g != 1`, and otherwise returns `x % m`
    - Follow the professor's posted mod_inverse pseudocode structure exactly, per Requirement 9 (fidelity to professor's hints) — do not substitute an iterative or differently-ordered extended Euclidean algorithm
    - _Requirements: 4.1, 4.4, 7.1, 7.4, 7.5, 9.2, 9.3, 9.4_

  - [x] 1.1 Write property test for RSA modular inverse correctness
    - **Property 7: RSA modular inverse correctness**
    - **Validates: Requirements 4.1, 4.4**

- [x] 2. Implement Diffie-Hellman primitives and IETF 1024-bit constants in helpers.py
  - [x] 2.1 Implement `dh_generate_private(q)`, `dh_public_value(g, x, q)`, `dh_shared_secret(peer_public, x, q)`
    - Private exponent generated in range `[2, q-2]`
    - _Requirements: 1.1, 1.4, 7.1_

  - [x] 2.2 Write property test for Diffie-Hellman shared secret agreement
    - **Property 1: Diffie-Hellman shared secret agreement**
    - **Validates: Requirements 1.1, 1.2, 1.4**

  - [x] 2.3 Add `DH_1024_Q_HEX`, `DH_1024_G`, and `dh_real_params()` with the exact IETF 1024-bit MODP hex constant
    - Convert hex to int via `int(hex_string, 16)` with no truncation, generator `g = 2`
    - _Requirements: 8.1, 8.2, 8.3_

  - [x] 2.4 Write unit test for IETF 1024-bit MODP constants
    - **Property 12: IETF 1024-bit MODP constants convert exactly**
    - **Validates: Requirements 8.1, 8.2, 8.3**

- [x] 3. Implement key derivation and AES-CBC wrappers in helpers.py
  - [x] 3.1 Implement `derive_aes_key(shared_secret_int)` using SHA-256 over the integer's byte representation, truncating the digest to 16 bytes to produce an AES-128 key
    - _Requirements: 1.5, 7.1_

  - [x] 3.2 Write property test for deterministic AES key derivation
    - **Property 2: AES key derivation is deterministic**
    - **Validates: Requirements 1.5**

  - [x] 3.3 Implement `aes_cbc_encrypt(key, plaintext_bytes)` and `aes_cbc_decrypt(key, iv_and_ciphertext)` using PyCryptodome, with random IV, PKCS7 padding, and `iv + ciphertext` framing
    - _Requirements: 2.5, 7.1, 7.5_

  - [x] 3.4 Write property test for MITM-derived key round trip
    - **Property 4: MITM-derived key matches and decrypts real traffic**
    - **Validates: Requirements 2.4, 2.5**

- [x] 4. Checkpoint - Ensure all helpers.py tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Implement RSA primitives in helpers.py
  - [x] 5.1 Implement `rsa_generate_keypair(bits=512, e=65537)` using `Crypto.Util.number.getPrime`, computing `n`, `phi`, and `d` via `mod_inverse`
    - Returns `((e, n), (d, n))`
    - _Requirements: 4.1, 7.1, 7.5_

  - [x] 5.2 Implement `rsa_encrypt(m, pub)`, `rsa_decrypt(c, priv)`, `rsa_sign(m, priv)`, `rsa_verify(s, pub)`
    - _Requirements: 4.2, 4.3, 6.1, 6.3, 7.1_

  - [x] 5.3 Write property test for RSA encrypt/decrypt round trip
    - **Property 8: RSA encrypt/decrypt round trip**
    - **Validates: Requirements 4.2, 4.3**

- [x] 6. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. Implement task1.py: Diffie-Hellman demos
  - [x] 7.1 Write toy-parameter DH exchange demo
    - Fixed small `q`/`g` (`q = 37`, `g = 5`, per the professor's posted hint — see Requirement 9), print `q`, `g`, private exponents, public values, both computed shared secrets, and an explicit match check
    - _Requirements: 1.1, 1.2, 9.1, 9.4_

  - [x] 7.2 Write unit test for toy-parameter DH exchange
    - Fixed (q, g, XA, XB) example with `q = 37`, `g = 5` produces matching secrets
    - _Requirements: 1.1, 1.2_

  - [x] 7.3 Write real-parameter (IETF 1024-bit) DH exchange demo
    - Uses `helpers.dh_real_params()`, random private exponents, prints hex constant used and resulting shared secret
    - _Requirements: 1.3, 1.4_

  - [x] 7.4 Derive and print a 16-byte AES-128 key from the shared secret using `helpers.derive_aes_key`
    - _Requirements: 1.5_

- [x] 8. Implement task2.py: MITM key-fixing attack demo
  - [x] 8.1 Set up Alice/Bob DH exchange and simulate Mallory substituting `q` for both `YA` and `YB`
    - _Requirements: 2.1, 2.2_

  - [x] 8.2 Show Alice and Bob each independently compute a shared secret of 0 mod q using the tampered value
    - _Requirements: 2.3_

  - [x] 8.3 Write property test for zero shared secret from base-value tampering
    - **Property 3: Tampering the DH base value with q forces a zero shared secret**
    - **Validates: Requirements 2.3, 3.3**

  - [x] 8.4 Derive Mallory's 16-byte AES-128 key from shared secret 0 and demonstrate decrypting an AES-CBC message Alice encrypts for Bob
    - _Requirements: 2.4, 2.5_

- [x] 9. Implement task2.py: generator-tampering attack demo
  - [x] 9.1 Run the DH exchange three times with `alpha = 1`, `alpha = q`, `alpha = q - 1`, keeping `q` fixed, printing results and an explanation for each case
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

  - [x] 9.2 Write property test for constant shared secret with alpha=1
    - **Property 5: Generator alpha=1 forces a constant shared secret**
    - **Validates: Requirements 3.2**

  - [x] 9.3 Write property test for two-value shared secret with alpha=q-1
    - **Property 6: Generator alpha=q-1 restricts the shared secret to two values by exponent parity**
    - **Validates: Requirements 3.4**

  - [x] 9.4 Write smoke test confirming all three generator-tampering cases run without error and print expected explanatory text
    - _Requirements: 3.5_

- [x] 10. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 11. Implement task3.py: RSA keygen/encrypt/decrypt self-test
  - [x] 11.1 Call `helpers.rsa_generate_keypair()`, pick a plaintext integer `m < n`, encrypt and decrypt, print all values and confirm the round trip
    - _Requirements: 4.1, 4.2, 4.3_

  - [x] 11.2 Write unit test confirming keygen produces n = p*q and phi = (p-1)*(q-1) for a generated keypair
    - _Requirements: 4.1_

- [x] 12. Implement task3.py: RSA malleability key-exchange attack
  - [x] 12.1 Implement r-multiplication variant: pick blinding factor `r`, compute `c_prime = (c * pow(r, e, n)) % n`, decrypt with the real private key, show result equals `(m * r) % n`
    - _Requirements: 5.1, 5.2, 5.4_

  - [x] 12.2 Write property test for RSA malleability via blinding factor multiplication
    - **Property 9: RSA malleability via blinding factor multiplication**
    - **Validates: Requirements 5.2, 5.4**

  - [x] 12.3 Implement direct-target variant: pick target `t`, compute `r = (t * helpers.mod_inverse(m, n)) % n`, compute `c_prime = (c * pow(r, e, n)) % n`, decrypt, show result equals `t` exactly
    - _Requirements: 5.3, 5.4_

  - [x] 12.4 Write property test for RSA malleability to an attacker-chosen target value
    - **Property 10: RSA malleability to an attacker-chosen target value**
    - **Validates: Requirements 5.3, 5.4**

  - [x] 12.5 Print explanation tying both malleability variants back to the key-exchange security implication
    - _Requirements: 5.5_

- [x] 13. Implement task3.py: RSA signature forgery demo
  - [x] 13.1 Sign two messages `m1`, `m2` with `helpers.rsa_sign`, compute `s3 = (s1 * s2) % n` and `m3 = (m1 * m2) % n` without touching the private key, verify `helpers.rsa_verify(s3, pub) == m3`
    - _Requirements: 6.1, 6.2, 6.3_

  - [x] 13.2 Write property test for RSA signature forgery via multiplicative combination
    - **Property 11: RSA signature forgery via multiplicative combination**
    - **Validates: Requirements 6.1, 6.2, 6.3**

  - [x] 13.3 Print explanation of why the multiplicative relationship breaks unforgeability for raw RSA signatures
    - _Requirements: 6.4_

- [x] 14. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP; they will not be implemented automatically.
- All code uses `#` line comments only, no docstrings, matching the student-natural style constraint.
- `egcd`/`mod_inverse` in `helpers.py` and the toy DH parameters (`q = 37`, `g = 5`) follow the professor's posted hints verbatim, per Requirement 9.
- Property tests target `helpers.py` functions directly per the design's testing strategy, keeping them decoupled from the print-heavy task scripts.
- Each task references specific requirements for traceability.
- Checkpoints ensure incremental validation before moving to the next task script.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["2.1", "5.1"] },
    { "id": 2, "tasks": ["2.2", "2.3", "3.1", "5.2"] },
    { "id": 3, "tasks": ["2.4", "3.2", "3.3", "5.3"] },
    { "id": 4, "tasks": ["3.4"] },
    { "id": 5, "tasks": ["7.1", "8.1", "11.1", "12.1", "13.1"] },
    { "id": 6, "tasks": ["7.2", "7.3", "8.2", "9.1", "11.2", "12.3", "13.3"] },
    { "id": 7, "tasks": ["7.4", "8.3", "9.2", "9.3", "12.2", "13.2"] },
    { "id": 8, "tasks": ["8.4", "9.4", "12.4", "12.5"] }
  ]
}
```
