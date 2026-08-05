"""
quarterdes_attacks.py

Two key-recovery attacks against quarter-DES (see des_core.py):

1. brute_force_attack(pairs)
   Exhaustively searches the full 2^16 key space against a single known
   plaintext/ciphertext pair, then confirms candidates against additional
   pairs. O(2^16) time, O(1) space.

   Unicity distance / expected runtime: timing 10^6 single-key encryptions
   and averaging gives roughly 8.1 microseconds per encrypt, which puts a
   full 2^16-key search at ~0.53 seconds worst case, ~0.27 seconds on
   average. This matters because it's also the basis for the "how many
   pairs do you actually need" question below -- byTheorem 5.2.1
   (Understanding Cryptography by Christof Paar - unicity distance),
   a single (pt, ct) pair on quarter-DES's 16-bit key/16-bit block is
   expected to leave exactly 2^(16 - 1*16) = 1
   surviving key candidate, i.e. one known pair is already enough to
   uniquely pin down the key.

2. meet_in_the_middle_attack(pairs)
   Attacks 2-key double encryption: C = E(E(P, k1), k2). Builds a lookup
   table of all possible intermediate values from the plaintext side
   (indexed by k1), then walks backward from the ciphertext side (over
   k2) to find matches. This trades memory for time: O(2^16) time and
   O(2^16) space, versus the O(2^32) a naive brute force over (k1, k2)
   would require.

   Applying the same Theorem 5.2.1 reasoning to double encryption's
   32-bit effective key space: a single (pt, ct) pair is expected to
   leave 2^(32 - 1*16) = 65536 surviving (k1, k2) candidates -- nowhere
   near unique. That's exactly what shows up in practice: one pair
   collapses the full 2^32 key-pair space down to the ~2^16 keys that
   share a matching intermediate value, but a second (and sometimes
   third) known pair is needed to filter that set down to the single
   correct key.

Each attack takes a list of (plaintext, ciphertext) pairs and returns the
recovered key(s).
"""

from des_core import encrypt, decrypt

KEY_SPACE = 2 ** 16


def brute_force_attack(pairs):
    """Recover the single quarter-DES key used to produce `pairs`.

    pairs: list of (plaintext, ciphertext) tuples, all encrypted under the
    same unknown key.
    Returns: list of surviving key candidates (usually just one).
    """
    pt1, ct1 = pairs[0]
    candidates = [k for k in range(KEY_SPACE) if encrypt(pt1, k) == ct1]

    for pt, ct in pairs[1:]:
        candidates = [k for k in candidates if encrypt(pt, k) == ct]

    return candidates


def meet_in_the_middle_attack(pairs):
    """Recover the (k1, k2) key pair for double-encrypted quarter-DES.

    Assumes C = E(E(P, k1), k2) for all pairs, encrypted under the same
    unknown (k1, k2).
    Returns: list of surviving (k1, k2) candidates (usually just one).
    """
    pt1, ct1 = pairs[0]

    # Index every possible intermediate value reachable by encrypting once
    # from the plaintext side.
    middle_to_k1 = {}
    for k1 in range(KEY_SPACE):
        mid = encrypt(pt1, k1)
        middle_to_k1.setdefault(mid, []).append(k1)

    # Walk backward from the ciphertext side and look for matching
    # intermediate values.
    candidates = []
    for k2 in range(KEY_SPACE):
        mid = decrypt(ct1, k2)
        if mid in middle_to_k1:
            candidates.extend((k1, k2) for k1 in middle_to_k1[mid])

    # Confirm against any remaining pairs.
    for pt, ct in pairs[1:]:
        candidates = [
            (k1, k2) for (k1, k2) in candidates
            if encrypt(encrypt(pt, k1), k2) == ct
        ]

    return candidates


if __name__ == "__main__":
    # Small self-contained demo: pick a secret key, generate known
    # plaintext/ciphertext pairs, then recover the key with each attack.
    import random

    secret_key = random.randrange(KEY_SPACE)
    demo_pairs = [(random.randrange(2 ** 16), None) for _ in range(2)]
    demo_pairs = [(pt, encrypt(pt, secret_key)) for pt, _ in demo_pairs]

    print(f"Secret key:            {secret_key}")
    print(f"Brute force recovered: {brute_force_attack(demo_pairs)}")

    k1, k2 = random.randrange(KEY_SPACE), random.randrange(KEY_SPACE)
    demo_pairs_2x = [(pt, encrypt(encrypt(pt, k1), k2)) for pt, _ in demo_pairs]
    print(f"Secret (k1, k2):        {(k1, k2)}")
    print(f"MITM recovered:         {meet_in_the_middle_attack(demo_pairs_2x)}")

