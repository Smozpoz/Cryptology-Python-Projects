"""
quarterdes_whitened_attack.py

Attacks a "whitened" variant of quarter-DES, where the ciphertext output
is additionally XORed with a second key:

    C = E(P, k1) XOR k2

Whitening is a real technique (used e.g. in DES-X) meant to make
brute-force key search more expensive by widening the effective key --
here the full (k1, k2) space is 2^16 * 2^16 = 2^32 keys, which at an
assumed ~10^-6 seconds per key check would take roughly 1.19 hours
worst-case to brute-force naively.

This script shows that naive XOR whitening doesn't actually buy that
security. Given two known plaintext/ciphertext pairs and a candidate k1,
k2 is fully determined algebraically: starting from
ct1 = qtE(pt1, k1) XOR k2 and XORing both sides by qtE(pt1, k1) gives

    k2 = ct1 XOR qtE(pt1, k1)

so for every candidate k1 there's exactly one k2 to check, not an
independent 2^16 to search. Checking whether that (k1, k2) pair is
actually correct is then just a second known pair away:
qtE(pt2, k1) XOR k2 == ct2 confirms it, and rejects it otherwise. That
means the attacker only ever iterates over k1's 2^16 possibilities --
the "extra" k2 key contributes nothing to the attacker's search cost,
which is exactly the flaw this script demonstrates: whitening quarter-DES
this way is only as strong as quarter-DES alone.
"""

from des_core import encrypt

KEY_SPACE = 2 ** 16


def whitened_encrypt(plaintext, k1, k2):
    """Encrypt with quarter-DES under k1, then XOR-whiten with k2."""
    return encrypt(plaintext, k1) ^ k2


def brute_force_whitened(pairs):
    """Recover (k1, k2) for whitened quarter-DES given three known pairs.

    pairs: list of at least 3 (plaintext, ciphertext) tuples, all produced
    under the same unknown (k1, k2).
    Returns: (k1, k2) if found, else None.
    """
    (pt1, ct1), (pt2, ct2), (pt3, ct3) = pairs[0], pairs[1], pairs[2]

    for k1 in range(KEY_SPACE):
        # k2 is fully determined once k1 is fixed, using the first pair.
        k2 = ct1 ^ encrypt(pt1, k1)

        if whitened_encrypt(pt2, k1, k2) == ct2:
            if whitened_encrypt(pt3, k1, k2) == ct3:
                return (k1, k2)

    return None


if __name__ == "__main__":
    import random

    k1_secret = random.randrange(KEY_SPACE)
    k2_secret = random.randrange(KEY_SPACE)

    plaintexts = [random.randrange(2 ** 16) for _ in range(3)]
    demo_pairs = [(pt, whitened_encrypt(pt, k1_secret, k2_secret)) for pt in plaintexts]

    print(f"Secret (k1, k2): {(k1_secret, k2_secret)}")
    print(f"Recovered:       {brute_force_whitened(demo_pairs)}")

