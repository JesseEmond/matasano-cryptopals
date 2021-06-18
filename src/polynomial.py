"""Functions to deal with polynomials f(x), e.g. f(x) = 3x^3 - 2x^2 + x - 5."""

from . import mod


class Polynomial:
    """Representation of a polynomial f(x) = c[n]*x^n + ... + c[1]*x + c[0]."""


    def __init__(self, coefficients):
        """Represents f(x) = c[n]*x^n + ... + c[1]*x  + c[0]."""
        assert len(coefficients) > 0
        self.coefficients = coefficients

    def eval(self, x):
        """Evaluates f(x)."""
        xs = [x**i for i in range(len(self.coefficients))]
        terms = [coefficient * x
                 for coefficient, x in zip(self.coefficients, xs)]
        return sum(terms)

    def derivative(self):
        """Returns f'(x)."""
        # d(a*x^n)/dx = a*n*x^(n-1), c[0] disappears, the rest "shifts left".
        coefficients = [coefficient * i
                        for i, coefficient in enumerate(self.coefficients)]
        return Polynomial(coefficients[1:])


def hensel_lift(f, p, k):
    """Returns roots for f mod p^k, lifting solutions starting from mod p.

    For k=1, we can find roots by trying all x in range(p) (brute-force).

    For k>1, we can sometimes use Hensel's Lemma to lift a root of f mod p^k to
    mod p^(k+1).
    Starting from f(r) = 0 (mod p^k) (root for mod p^k):
    - If f'(r) != 0 (mod p), then the simple form of Hensel's Lemma applies,
      and we can find the unique root mod p^(k+1) by lifting our root r. There
      is a unique t (modulo p) such that f(r + tp^k) = 0 (mod p^(k+1)).
      The new root is (r - f(r) * f'(r)^(-1)) (mod p^(k+1)).
    - If f'(r) = 0 (mod p), then we have two cases:
      - f(r) != 0 (mod p^(k+1)), in which case there is *no* lifting of 'r' to
        a root of f mod p^(k+1).
      - f(r) = 0 (mod p^(k+1)), in which case *every* lifting of 'r' is a root
        of f mod p^(k+1). So r + tp^k for any integer t are all roots.
    
    See details/resources at:
    https://github.com/JesseEmond/theoretical/tree/main/cube-suffix
    """
    assert k > 0
    Zp = mod.GF(p)
    if k == 1:
        # Find the roots (mod p) via bruteforce.
        return [x for x in range(p) if Zp(f.eval(x)) == 0]
    # We'll be lifting solutions starting from f(x) = 0 (mod p^(k-1)).
    roots = hensel_lift(f, p, k - 1)
    new_roots = []
    df = f.derivative()
    Zpk = mod.GF(p, k)
    for r in roots:
        if Zp(df.eval(r)) != 0:  # f'(r) != 0, can apply Hensel's Lemma.
            # We can lift to the unique solution mod p^k.
            df_r_inv = (Zp(1) / df.eval(r)).int()
            new_root = ((Zpk(r) - f.eval(r)) * df_r_inv).int()
            assert Zpk(f.eval(new_root)) == 0
            new_roots.append(new_root)
        elif Zpk(f.eval(r)) == 0:
            # f'(r) = 0 (mod p), can't apply Hensel's Lemma directly.
            # If f(r) = 0 (mod p^k), however, then every lifting of
            # r to mod p^k is a root of f(x) mod p^k. Note that if it is not,
            # then there is no lifting of r to mod p^k.
            for t in range(p):
                new_root = (Zpk(r) + t * p**(k - 1)).int()
                assert Zpk(f.eval(new_root))
                new_roots.append(new_root)
    return new_roots
