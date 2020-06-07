import random
from time import sleep
import time

from .. import prng


# sanity check
r = prng.random(10)
values1 = [r.random() for _ in range(1000)]
r = prng.random(10)
values2 = [r.random() for _ in range(1000)]
assert(values1 == values2)

def get_output():
    global secret_seed
    wait = random.randint(40, 1000)
    sleep(wait / 100)  # we're not *that* patient...

    now = time.time()
    secret_seed = int(now)
    print("Seed is: %d" % secret_seed)
    r = prng.random(secret_seed)

    wait = random.randint(40, 1000)
    sleep(wait / 100)  # we're not *that* patient...

    return r.random()


output = get_output()
now = int(time.time())

start_guess = now - 1000
end_guess = now + 1
print("Trying seeds from %d to %d..." % (start_guess, end_guess))

for seed in range(start_guess, end_guess):
    r = prng.random(seed)
    if r.random() == output:
        print("Found seed! %d" % seed)
        assert(seed == secret_seed)
        exit()
assert(False)
