"""
des_core.py

Core building blocks for "quarter-DES", a scaled-down version of DES used
for classroom cryptanalysis: 16-bit blocks, 16-bit keys, 2 S-boxes (taken
directly from real DES), and a 6-round Feistel structure.

This module holds ONLY the cipher itself. The attacks that exploit it
(brute-force, meet-in-the-middle, and an attack on a whitened variant)
live in quarterdes_attacks.py and quarterdes_whitened_attack.py.
"""

# The first two S-boxes from real DES, reused here unmodified.
SBOX_DATA = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
]

# Expansion permutation: bit i of the output comes from bit EXPANSION[i] of
# the (1-indexed) 8-bit input.
EXPANSION = [8, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 1]


def s_box(k, x):
    """Evaluate S-box k (1 or 2) on a 6-bit input x."""
    x = x & 0x3F
    row = ((x >> 5) << 1) + (x & 1)
    col = (x >> 1) & 0xF
    return SBOX_DATA[k - 1][row][col]


def round_key(k, i):
    """Derive the 12-bit round key for round i from the full 16-bit key k."""
    return (((k << 16) + k) >> i) & 0xFFF


def expand(x):
    """Expand an 8-bit half-block to 12 bits per the EXPANSION table."""
    n = len(EXPANSION)
    return sum(((x >> (8 - EXPANSION[i])) & 1) << (n - i) for i in range(n))


def feistel_f(x, rk):
    """Feistel round function: expand, mix with round key, run through S-boxes."""
    expanded = expand(x) ^ rk
    out = 0
    for i in range(1, -1, -1):
        s_input = expanded & 0x3F
        out = (out << 4) + s_box(i, s_input)
        expanded >>= 6
    return out


def feistel_round(x, rk):
    """One Feistel round on a 16-bit block x with 12-bit round key rk."""
    left = x >> 8
    right = x & 0xFF
    return (right << 8) + (left ^ feistel_f(right, rk))


def encrypt(x, k):
    """Encrypt a 16-bit plaintext block x under 16-bit key k (6 rounds)."""
    x &= 0xFFFF
    k &= 0xFFFF
    for i in range(6):
        x = feistel_round(x, round_key(k, i))
    return ((x & 0xFF) << 8) + (x >> 8)


def decrypt(x, k):
    """Decrypt a 16-bit ciphertext block x under 16-bit key k (6 rounds)."""
    x &= 0xFFFF
    k &= 0xFFFF
    for i in range(6):
        x = feistel_round(x, round_key(k, 5 - i))
    return ((x & 0xFF) << 8) + (x >> 8)

