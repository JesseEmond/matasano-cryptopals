from . import random_helper


def all_primes_under(n):
    """Generates a list of primes under 'n', using the sieve of Eratosthenes."""
    # 0, 1, 2 are composite, composite, prime, mark the rest 'prime' to start
    is_prime = [False, False, True] + [True for _ in range(2, n)]
    p = 2
    while p * p < n:
        for not_prime in range(p * 2, n, p):
            is_prime[not_prime] = False
        p += 1
    return [idx for idx, n_is_prime in enumerate(is_prime) if n_is_prime]


_SMALL_PRIME_LIMIT = 65000
_SMALL_PRIMES = set(all_primes_under(_SMALL_PRIME_LIMIT))


def is_prime(n):
    """Returns whether 'n' is a prime number."""
    assert n > 0
    if n == 1: return False
    if n <= _SMALL_PRIME_LIMIT: return n in _SMALL_PRIMES
    if any(n % p == 0 for p in _SMALL_PRIMES): return False
    return miller_rabin(n)


def miller_rabin(n, rounds=50):
    """Performs a Miller-Rabin test to see if 'n' is a strong probable prime.

    'n' should be an odd number > 3.

    See miller_rabin_round for a description of the algorithm.

    Probability of 'n' being a strong pseudoprime (passing the test as a
    composite number): <= 1 / 4^rounds.

    With 'rounds' of 50, see the following link that puts it in perspective
    compared to the probability of a cosmic ray flipping the 1-bit output of a
    deterministic test: https://stackoverflow.com/a/4160517
    """
    assert n > 3 and n % 2 == 1
    return all(miller_rabin_round(n) for _ in range(rounds))


def miller_rabin_round(n):
    """Picks a random base 'a' and checks if it passes the Miller-Rabin test.

    'n' should be an odd number > 3.

    The test works by checking if, for a base 'a', the number maintains
    properties true for all prime numbers, but only some composite numbers.

    We start from Fermat's little theorem:
        a^(n-1) = 1 (mod n)  (for n prime)
    We can rewrite a^(n-1) as a^(2^s * d), where d is odd (factor out powers of
    2).

    If 'n' is prime, then (mod n) is a field and:
        x^2 = 1 (mod n) has only two roots: x = 1 (mod n) and x = -1 (mod n)
    To prove that there are only two roots, we can use Euclid's lemma:
        x^2 - 1 = (x + 1)(x - 1) = 0  (mod n)
    Then it follows that since 'n' divides (x + 1)(x - 1), it divides one of the
    factors.

    So, from a^(n-1) = 1 (mod n), if 'n' is prime, we can take square roots as
    long as the result is 1, and we should get -1 eventually (or reach a^d = 1).
    
    In other words, a prime number will have:
        a^d = 1 (mod n)
    or
        a^(2^r * d) = -1 (mod n), for some 0 <= r < s.

    From the contrapositive, 'n' is composite if:
        a^d != 1 (mod n)
    and
        a^(2^r * d) != -1 (mod n), for all 0 <= r < s.

    Probability of 'n' being a strong pseudoprime: <= 1/4.
    (See http://www.mat.uniroma2.it/~schoof/millerrabinpom.pdf)
    """
    assert n > 3 and n % 2 == 1
    a = random_helper.random_number(between=[2, n - 2])
    s, d = factor_powers_of_2(n - 1)
    if pow(a, d, n) == 1:
        # We'll keep doing pow with 1 as a base and end up with 1. 'a' is not a
        # "witness" for the compositeness of 'n'.
        return True  # Maybe prime.
    # A composite number will have a^(2^r * d) != -1 for all 0 <= r < s.
    is_witness = all(pow(a, 2**r * d, n) != n - 1 for r in range(s))
    return not is_witness  # Not a composite witness? Maybe prime.


def factor_powers_of_2(n):
    """Rewrites n as 2^s * d, where d is odd. Returns (s, d)"""
    s, d = 0, n
    while d % 2 == 0:
        d //= 2
        s += 1
    return s, d


def random_prime(bits):
    """Returns a random prime with the number of bits specified."""
    while True:
        n = random_helper.random_number(bits=bits)
        n |= 1  # Force it to be odd.
        if is_prime(n):
            return n


assert factor_powers_of_2(221 - 1) == (2, 55)

assert is_prime(2) and is_prime(3) and not is_prime(4)
assert is_prime(199)
assert is_prime(199) and is_prime(2**89-1)
assert not is_prime(221) and not is_prime(3**43 * 5**51 * 7**13)
