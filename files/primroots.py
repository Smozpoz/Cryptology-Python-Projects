"""
primroots.py

Naive (brute-force) tools for reasoning about primitive roots modulo a
prime p. Primitive roots are the generators used to set up discrete-log
based systems like Diffie-Hellman -- diffie_hellman_attack.py shows what
goes wrong when a "generator" is chosen poorly (small order instead of a
true primitive root).

These implementations are intentionally simple/unoptimized: they exist to
build intuition about *what* a primitive root is, not to be fast for
large p.
"""


def is_primitive_root(r, p):
    """Check whether r is a primitive root modulo prime p.

    r is a primitive root mod p if its powers r^0, r^1, ..., r^(p-2)
    produce every nonzero residue mod p exactly once.
    """
    powers = {pow(r, i, p) for i in range(p - 1)}
    return len(powers) == p - 1


def count_primitive_roots(p):
    """Count how many primitive roots exist modulo prime p."""
    return sum(1 for r in range(1, p - 1) if is_primitive_root(r, p))


def find_smallest_primitive_root(p):
    """Find the smallest primitive root modulo prime p."""
    for r in range(1, p - 1):
        if is_primitive_root(r, p):
            return r
    raise ValueError(f"No primitive root found for p={p}")


if __name__ == "__main__":
    p = 761  # a small prime for demonstration
    print(f"Smallest primitive root mod {p}: {find_smallest_primitive_root(p)}")
    print(f"Total primitive roots mod {p}:   {count_primitive_roots(p)}")

