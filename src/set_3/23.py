from ..prng import random, clone_mt19937


rand = random(42)
outputs = [rand.random() for _ in range(1000)]

cloned = clone_mt19937(outputs)

for _ in range(1000):
    assert(cloned.random() == rand.random())
