"""
numbertheory.py

Modular arithmetic utilities used throughout the other attack scripts
(e.g. Diffie-Hellman, RSA-style reasoning about invertibility).

mod_exp(a, m, n):  compute a^m mod n via fast (square-and-multiply)
                    modular exponentiation, O(log m) instead of O(m).
mod_inv(a, n):      compute the modular inverse of a mod n via the
                    extended Euclidean algorithm.
"""


def mod_exp(a, m, n):
    """Compute a^m mod n using fast modular exponentiation (square-and-multiply)."""
    if m < 0:
        raise ValueError("mod_exp does not support negative exponents; "
                          "use mod_inv(mod_exp(a, -m, n), n) instead")

    result = 1
    base = a % n
    while m > 0:
        if m % 2 == 1:
            result = (result * base) % n
        base = (base * base) % n
        m //= 2
    return result


def mod_inv(a, n):
    """Compute the modular inverse of a mod n via the extended Euclidean algorithm.

    Raises ValueError if a is not invertible mod n (i.e. gcd(a, n) != 1).
    """
    n = abs(n)
    a = a % n
    old_r, r = n, a
    old_t, t = 0, 1

    while r > 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_t, t = t, old_t - q * t

    if old_r > 1:
        raise ValueError(f"{a} is not invertible mod {n}")

    return old_t % n


if __name__ == "__main__":
    a, m, n = 7, 560, 561
    print(f"{a}^{m} mod {n} = {mod_exp(a, m, n)}")

    a, n = 17, 3120
    inv = mod_inv(a, n)
    print(f"Inverse of {a} mod {n} = {inv}  (check: {(a * inv) % n} == 1)")

