# Public-Key Crypto Lab (CSC-3201 Module 3)

Python demonstrations of Diffie-Hellman key exchange, man-in-the-middle attacks against unauthenticated DH, and textbook RSA (including its malleability weaknesses). Built for a CSC-3201 assignment on public-key cryptography.

## What's here

| File | What it demonstrates |
|---|---|
| `helpers.py` | Shared crypto primitives: hand-rolled extended Euclidean algorithm / modular inverse, DH key generation and shared-secret computation, SHA-256-based AES key derivation, AES-CBC encrypt/decrypt, and textbook RSA keygen/encrypt/decrypt/sign/verify |
| `task1.py` | Diffie-Hellman key exchange using toy parameters (`q = 37`, `g = 5`) and real IETF 1024-bit MODP parameters, followed by AES-CBC message exchange using the derived key |
| `task2.py` | Two MITM attacks on unauthenticated DH: a key-fixing attack (Mallory substitutes `q` for both public values, forcing the shared secret to 0) and a generator-tampering attack (using `alpha = 1`, `alpha = q`, and `alpha = q - 1` in place of the real generator) |
| `task3.py` | Textbook RSA keygen/encrypt/decrypt, an RSA signature forgery attack via multiplicative malleability, and RSA ciphertext malleability attacks against a naive key-exchange protocol |

Each script is self-contained and runs top to bottom, printing intermediate values (keys, ciphertexts, shared secrets) so the output can be read like a transcript of the attack or protocol.

## Why these attacks work (short version)

- **DH key-fixing:** if an attacker can replace both parties' public values in transit, they can force the shared secret to a known constant without ever learning either private exponent.
- **DH generator tampering:** a malicious or corrupted generator (`1`, `q`, or `q-1`) collapses the shared secret into a tiny, guessable set of values regardless of the private exponents chosen.
- **RSA malleability:** because textbook RSA has no padding, `E(m1) * E(m2) mod n == E(m1 * m2 mod n)`. This lets an attacker scale a ciphertext by a known factor, steer a decrypted value to an arbitrary target, or forge a valid signature on a new message by combining two known signatures.

## Requirements

- Python 3.9+
- [PyCryptodome](https://pycryptodome.readthedocs.io/) for AES-CBC, SHA-256, and prime generation
- `pytest` and `hypothesis` (only needed to run the test suite)

Install dependencies:

```bash
pip install -r requirements.txt
```

## Running the demos

```bash
python task1.py
python task2.py
python task3.py
```

Each script exits with an assertion error if any of its own internal correctness checks fail (e.g. Alice and Bob disagreeing on a shared secret, a decrypted message not matching the original).

## Running the tests

```bash
pytest
```

The suite in `tests/` includes property-based tests (via Hypothesis) for the DH shared-secret agreement, RSA round-trip correctness, RSA malleability properties, and the modular inverse implementation, plus example/unit tests and a smoke test for `task2.py`'s output.

## Project structure

```
Module3Assignment/
├── helpers.py          # shared crypto primitives
├── task1.py             # DH exchange (toy + real params)
├── task2.py             # MITM key-fixing + generator-tampering attacks
├── task3.py             # RSA keygen/enc/dec, malleability, signature forgery
├── requirements.txt
├── pytest.ini
└── tests/
    ├── test_helpers.py
    └── test_task2_smoke.py
```

## Disclaimer

This is coursework written for educational purposes to illustrate why unauthenticated Diffie-Hellman and unpadded ("textbook") RSA are insecure. None of this code is intended for use in a real cryptographic system — real-world DH needs authentication (e.g. signed key exchanges, TLS-style certificates) and real-world RSA needs proper padding (e.g. OAEP for encryption, PSS for signatures).
