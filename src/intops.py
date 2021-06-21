def ceil_div(a, b):
    """Computes ceil(a / b), even for very large ints."""
    # From https://stackoverflow.com/a/17511341/395386
    return -(-a // b)
