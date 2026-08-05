# Cryptology Attacks

Python implementations of classical cryptanalysis attacks, written for an
undergraduate cryptology course (CSC 333). Each script targets a specific
weakness in a cryptosystem — a bad generator, a small key space, a broken
whitening scheme, or a biased S-box — and recovers the key (or shows how
to) using nothing but math and computation.

## Attacks

### `diffie_hellman_attack.py` — Recovering private exponents from a bad generator

Diffie-Hellman's security depends on the discrete log problem being hard,
which in turn depends on the generator being a true primitive root — one
whose powers cycle through every nonzero residue mod p before repeating.
If the "generator" doesn't actually have that property, its powers can
repeat much sooner, and an attacker can just walk `r^1, r^2, r^3, ...`
one step at a time until a power matches an observed public value,
recovering the private exponent directly.

In the scenario this script solves, Alice and Bob are sold a bad
generator by an outside "consultant." Running the attack recovers both
private exponents (`a = 70`, `b = 68`), and both independently
reconstruct the same shared secret — confirming the attack works and
that DH's guarantees depend on correct parameter selection, not just on
discrete log being hard in general.

### `quarterdes_attacks.py` — Brute-force and meet-in-the-middle key recovery on quarter-DES

Two attacks against `des_core.py`'s quarter-DES cipher:

- **`brute_force_attack(pairs)`** exhaustively searches the full 2^16 key
  space against one known plaintext/ciphertext pair, then confirms
  candidates against any additional pairs.
- **`meet_in_the_middle_attack(pairs)`** attacks 2-key double encryption
  (`C = E(E(P, k1), k2)`) by building a lookup table of intermediate
  values from the plaintext side, then matching against the ciphertext
  side worked backward — trading memory for time (`O(2^16)` time and
  space, versus the `O(2^32)` a naive search over `(k1, k2)` would need).

**How many known pairs does each attack actually need?** This comes down
to *unicity distance* (Theorem 5.2.1): given a key space of size `2^k`,
a block size of `2^n`, and `t` known pairs, the expected number of
surviving key candidates is `2^(k - t*n)`.

- For brute force, `k = n = 16`, so even a single known pair already
  gives `2^(16 - 16) = 1` — one pair is expected to uniquely determine
  the key.
- For meet-in-the-middle, the effective key space is `k = 32` against the
  same 16-bit block, so one pair gives `2^(32 - 16) = 65536` surviving
  candidates — nowhere near unique. That's exactly what shows up when
  running the attack: a second (and sometimes third) known pair is
  needed to filter that candidate set down to the single correct key.

Timing it out: measuring quarter-DES's actual per-encryption speed
(~8.1 microseconds, averaged over a million encryptions) puts a full
2^16-key brute-force search at roughly **0.53 seconds worst-case,
0.27 seconds on average** — small enough that a reduced-size cipher like
this makes brute force genuinely demonstrable on a laptop, unlike real
DES's 56-bit key space.

### `quarterdes_whitened_attack.py` — Breaking quarter-DES with XOR key whitening

Key whitening (used for real in DES-X) tries to widen a cipher's
effective key by XORing a second key onto the output:
`C = E(P, k1) XOR k2`. On paper this looks like a `2^16 * 2^16 = 2^32`
key cryptosystem — brute-forcing it naively would take roughly
**1.19 hours** at an assumed 10^-6 seconds per key check.

In practice it doesn't add that security. Given two known
plaintext/ciphertext pairs and a candidate `k1`, `k2` is fully determined
algebraically: starting from `ct1 = qtE(pt1, k1) XOR k2` and XORing both
sides by `qtE(pt1, k1)` gives

```
k2 = ct1 XOR qtE(pt1, k1)
```

So for every candidate `k1` there's exactly one `k2` to check — not an
independent `2^16` to search — and a second known pair (`qtE(pt2, k1) XOR
k2 == ct2`) confirms or rejects the candidate. The attacker only ever
iterates over `k1`'s `2^16` possibilities, so naive XOR whitening this way
is only as strong as quarter-DES alone — the "extra" key contributes
nothing to the attacker's search cost.

### `des_s4_differential.py` — Differential analysis of DES's S4 S-box

DES's designers specified a hard requirement on every real S-box: for
any nonzero 6-bit input difference, no more than 8 of the 32 input pairs
sharing that difference may produce the same output difference. Scanning
every `(idiff, odiff)` pair for S4 confirms that requirement holds
**exactly at its boundary** — the strongest differentials found top out
at a count of exactly 8, never higher. That's the same bound the S-box
was explicitly designed not to exceed, with no slack — part of why
differential cryptanalysis against full 16-round DES, while theoretically
effective, still needs an impractically large number of chosen
plaintexts in practice.

### `shift_cipher_breaker.py` — Breaking a shift (Caesar) cipher via frequency analysis

Classic known-ciphertext-only attack: try all 26 shifts, score each
candidate decryption by how closely its letter frequencies match
standard English, and return the best-scoring shift.

A natural follow-up: is scoring by *sum of absolute* frequency
differences the best approach, or would *sum of squared* differences
(penalizing large mismatches more heavily) do better? Testing both
against randomly-sampled substrings of a public-domain text (King James
Bible, via Project Gutenberg), across text lengths 10–24 and 1000 trials
per length, the absolute-difference version consistently outperformed
the squared-difference version at *every* length tested — from
**78.2% vs. 74.9%** correct at length 10 up to **99.2% vs. 98.0%**
correct at length 24. The gap held up even after rerunning with more
trials, so for this particular scoring problem, penalizing every
frequency mismatch equally beats penalizing large mismatches more.

## Supporting modules

| Module | Purpose |
|---|---|
| [`des_core.py`](des_core.py) | Shared quarter-DES implementation (S-boxes, Feistel rounds, encrypt/decrypt) used by both DES attack scripts |
| [`numbertheory.py`](numbertheory.py) | Fast modular exponentiation and modular inverse (extended Euclidean algorithm) |
| [`primroots.py`](primroots.py) | Tools for identifying primitive roots mod p — relevant to why the Diffie-Hellman attack above works |

## Background: quarter-DES

Several scripts here target "quarter-DES," a scaled-down teaching version
of DES: 16-bit blocks, 16-bit keys, 2 real DES S-boxes, and 6 Feistel
rounds (instead of DES's 64-bit blocks, 56-bit keys, 8 S-boxes, and 16
rounds). The reduced size makes exhaustive key search and full attack
demonstrations feasible on a laptop, while preserving DES's actual
Feistel structure and S-boxes — so the attacks illustrate real
techniques (brute force, meet-in-the-middle, differential analysis)
rather than being toy examples with no relation to the real cipher.

## Running the scripts

No external dependencies — everything uses the Python standard library.
Requires Python 3.8+.

Each script can be run directly and includes a small self-contained demo:

```bash
python3 diffie_hellman_attack.py
python3 shift_cipher_breaker.py
python3 quarterdes_attacks.py          # takes a few seconds (2^16 key search)
python3 quarterdes_whitened_attack.py  # takes a few seconds
python3 des_s4_differential.py
python3 numbertheory.py
python3 primroots.py
```

To use an attack on your own data, import the function directly:

```python
from quarterdes_attacks import brute_force_attack

pairs = [(0x1234, 0x5678), (0x4321, 0x8765)]  # known plaintext/ciphertext
recovered_keys = brute_force_attack(pairs)
```

## Notes

- `quarterdes_attacks.py` and `quarterdes_whitened_attack.py` each search
  a 2^16 key space, so expect a few seconds of runtime, not instant
  output.
- With only two known plaintext/ciphertext pairs, the meet-in-the-middle
  attack can occasionally return more than one candidate key pair — this
  is expected and reflects a real property of MITM attacks (more known
  pairs shrink the candidate set further).
