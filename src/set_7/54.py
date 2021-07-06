import itertools
import time

from .. import aes
from .. import merkle_damgard
from .. import random_helper


class MyHash(merkle_damgard.Hash):
    BLOCK_SIZE = 2  # 16 bits
    STATE_ENTRY_SIZE = 1
    STATE_ENTRIES = 2

    def __init__(self, h=None, msg_len=0):
        h = h or (0x12, 0x24)
        super().__init__(h, msg_len)

    @classmethod
    def process_chunk(cls, chunk, state):
        assert len(chunk) == 2
        block = b"\x00" * 14 + chunk
        key = b"\x00" * 14 + bytes(state)
        out = aes.aes_encrypt_block(key, block)
        h = out[:2]
        return tuple(h)


SCORES_LEN = 4368


def get_baseball_scores():
    teams = [
        "Baltimore Orioles", "Boston Red Sox", "New York Yankees",
        "Tampa Bay Rays", "Toronto Blue Jays", "Chicago White Sox",
        "Cleveland Indians", "Detroit Tigers", "Kansas City Royals",
        "Minnesota Twins", "Houston Astros", "Los Angeles Angels",
        "Oakland Athletics", "Seattle Mariners", "Texas Rangers"
        ]
    output = ""
    for team1, team2 in itertools.combinations(teams, 2):
        score1 = random_helper.random_number(below=5)
        score2 = random_helper.random_number(below=5)
        output += f"{team1} {score1}  -  {score2} {team2}\n"
    assert len(output) == SCORES_LEN  # Makes it easier to check bounds.
    return output


def pretty_print(scores):
    lines = scores.split("\n")
    print("\n".join(lines[:5]) + "\n[...]\n" + "\n".join(lines[-5:]))


def show_off(k):
    msg_len = 5000  # Roughly, we'll pad up to it.
    glue_len = (k+1) * MyHash.BLOCK_SIZE
    assert glue_len + SCORES_LEN <= msg_len, "Msg len too small."
    digest, generator = MyHash.nostradamus(k=k, msg_len=msg_len, verbose=True)
    print("I am Nostradamus. I know the baseball future. Here is my proof:")
    print(digest.hex())

    print("[baseball happens]")
    print("  ", end="", flush=True)
    for _ in range(4):
        time.sleep(0.5)
        print(".", end="", flush=True)
    print("\nBaseball season over!")

    scores = get_baseball_scores()
    print("The scores were (snippet):")
    pretty_print(scores)

    print("Just as a I predicted! My prediction was...")
    prediction_prefix = (b"My prediction:\n" +
                         scores.encode("ascii") +
                         b"\n\nMy secret notes (ignore):\n")
    prediction = generator.get_message(prediction_prefix, pad_char=" ")
    print(prediction.decode("ascii", "backslashreplace"))
    print(f"Hash: {MyHash().update(prediction).digest().hex()}")

    assert MyHash().update(prediction).digest() == generator.digest


b = MyHash.state_size() * 8
print(f"Working with a {b}-bits hash.")

print(f"Pre-processing 2**{b//2} blocks.")
show_off(k=b//2)

print(f"\n\n\n\nAgain, but with 2**{b//2+2} pre-processed blocks.")
show_off(k=b//2+2)

print(f"\n\n\n\nAgain, but with 2**{b//2-7} pre-processed blocks.")
show_off(k=b//2-7)
