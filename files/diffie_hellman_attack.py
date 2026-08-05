"""
diffie_hellman_attack.py

Breaks a Diffie-Hellman key exchange that (mistakenly) uses a generator r
with small multiplicative order modulo p, instead of a true primitive
root of the full group.

Why this works: a real primitive root has order p-1, so its powers cycle
through every nonzero residue mod p before repeating -- that huge cycle
length is exactly what makes the discrete log problem hard to invert.
If r is not a primitive root, it can repeat values r^a for multiple
distinct exponents a, which shrinks the effective search space and makes
it far more feasible for an attacker to just walk r^1, r^2, r^3, ... one
step at a time until it matches an observed public value.

In the underlying homework scenario, a consultant ("Evan") sells Alice
and Bob a generator r that isn't actually a primitive root of p. Recovering
their private exponents this way gives a=70, b=68, which both independently
reconstruct the same shared secret (77539848879887155543851570233103783253795592553178671)
-- confirming the attack works and that DH's guarantees fully depend on
correct parameter selection, not just on the general hardness of discrete log.
"""

# Public parameters and observed public keys for this exercise.
P = 290340590948509283409285098340598209348094830593405759
R = 142922050268516564678315738617307920248171449173861624
PUBLIC_KEY_1 = 163390425341384268623072281134575191676371923487952637
PUBLIC_KEY_2 = 108031287604710654730981481470350948701714286472760884


def discrete_log_small_order(target, r, p):
    """Recover exponent a such that r^a mod p == target, by brute force.

    Only feasible because r has small multiplicative order mod p; for a
    generator of the full group this would be computationally infeasible
    (the discrete log problem), which is what makes real DH secure.
    """
    x = 1
    exponent = 0
    while x != target:
        x = (x * r) % p
        exponent += 1
    return exponent


def break_diffie_hellman():
    """Recover both parties' private exponents from their public keys."""
    a = discrete_log_small_order(PUBLIC_KEY_1, R, P)
    b = discrete_log_small_order(PUBLIC_KEY_2, R, P)
    return a, b


if __name__ == "__main__":
    a, b = break_diffie_hellman()
    print(f"Recovered private exponent a: {a}")
    print(f"Recovered private exponent b: {b}")

    # Both parties should now be able to compute the same shared secret.
    shared_secret_A = pow(PUBLIC_KEY_2, a, P)
    shared_secret_B = pow(PUBLIC_KEY_1, b, P)
    assert shared_secret_A == shared_secret_B
    print(f"Recovered shared secret:      {shared_secret_A}")

