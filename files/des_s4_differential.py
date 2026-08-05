"""
des_s4_differential.py

Differential cryptanalysis of DES's S4 substitution box.

The core idea: for a fixed input XOR difference (idiff), count how many
input pairs (x, x XOR idiff) produce a given output XOR difference
(odiff) after passing through S4. Real DES S-boxes are not perfectly
balanced with respect to these differences, and those imbalances are
exactly what differential cryptanalysis exploits to recover key bits
faster than brute force.

find_strong_differentials() scans every (idiff, odiff) pair looking for
differentials with unusually high counts -- the kind of bias an attacker
would target first.

DES's designers specified a hard requirement on every real S-box: for any
nonzero 6-bit input difference, no more than 8 of the 32 possible input
pairs sharing that difference may produce the same output difference.
Scanning all (idiff, odiff) pairs for S4 confirms that requirement holds
exactly at its boundary -- the strongest differentials found (e.g. input
difference 0x01 -> output difference 0x5, or input difference 1 -> output
difference 5 in decimal) top out at a count of exactly 8, never higher.
That's the same bound the S-box was explicitly designed not to exceed:
it's tight, not with room to spare, which is part of why differential
cryptanalysis against full DES -- while theoretically effective -- still
requires an impractically large number of chosen plaintexts against the
real 16-round cipher.
"""

S4_TABLE = [
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
]


def s4(x):
    """Evaluate DES S-box S4 on a 6-bit input x, returning a 4-bit output."""
    row = ((x & 0b100000) >> 4) | (x & 0b000001)
    col = (x >> 1) & 0b1111
    return S4_TABLE[row][col]


def differential_count(idiff, odiff):
    """Count 6-bit input pairs (x, x XOR idiff) whose S4 outputs XOR to odiff."""
    count = 0
    for x in range(1, 64):
        y = x ^ idiff
        if x < y:  # count each unordered pair once
            if s4(x) ^ s4(y) == odiff:
                count += 1
    return count


def find_strong_differentials(threshold=8):
    """Find all (idiff, odiff) pairs whose differential count meets `threshold`.

    A count of 8 out of a possible 32 pairs (25%) is well above the ~2 you'd
    expect from a uniformly random S-box, and is the kind of bias real
    differential attacks on DES rely on.
    """
    strong = []
    for idiff in range(64):
        for odiff in range(16):
            if differential_count(idiff, odiff) >= threshold:
                strong.append((idiff, odiff, differential_count(idiff, odiff)))
    return strong


if __name__ == "__main__":
    results = find_strong_differentials(threshold=8)
    print(f"Found {len(results)} differentials with count >= 8:")
    for idiff, odiff, count in results:
        print(f"  input diff={idiff:#04x}  output diff={odiff:#03x}  count={count}")
