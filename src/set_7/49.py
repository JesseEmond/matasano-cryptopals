import dataclasses

from .. import aes
from .. import mac
from .. import random_helper
from .. import xor


@dataclasses.dataclass
class Account:
    id_: int
    name: str
    password: str  # Stored as plaintext. Bad. Oh well!
    spacebucks: int


class Secrets:

    def __init__(self):
        seed_accounts = [
            Account(id_=0, name="Alice", spacebucks=1000500,
                    password="@l1c3!"),
            Account(id_=1, name="Bob", spacebucks=100, password="b0b"),
            Account(id_=2, name="Mallory", spacebucks=1, password="hunter2"),
        ]
        self.accounts = {acc.id_: acc for acc in seed_accounts}
        self.key = random_helper.random_bytes(16)


class BankApi:
    """What would be our API endpoint."""

    def __init__(self, secrets):
        self.secrets = secrets

    def transfer_v1(self, message):
        """V1: msg||iv||mac."""
        mac_, message = message[-16:], message[:-16]
        iv, message = message[-16:], message[:-16]
        if mac.cbc_mac(self.secrets.key, message, iv) != mac_:
            raise ValueError("Invalid CBC-MAC.")
        parts = [part.split(b"=") for part in message.split(b"&")]
        values = {key: int(value) for key, value in parts}
        from_acc = self.secrets.accounts[values[b"from"]]
        to_acc = self.secrets.accounts[values[b"to"]]
        amount = values[b"amount"]
        assert from_acc.spacebucks >= amount
        from_acc.spacebucks -= amount
        to_acc.spacebucks += amount

    def transfer_v2(self, message):
        """V2: msg||mac  (fixed iv)"""
        # Be lenient with validation to allow a scrambled block to go through.
        mac_, message = message[-16:], message[:-16]
        if mac.cbc_mac(self.secrets.key, message) != mac_:
            raise ValueError("Invalid CBC-MAC.")
        values = {}
        for key_value in message.split(b"&"):
            parts = key_value.split(b"=")
            if len(parts) == 2:
                key, value = parts
                values[key] = value
        from_acc = self.secrets.accounts[int(values[b"from"])]
        txns = values[b"tx_list"].split(b";")
        transfers = []
        for txn in txns:
            parts = txn.split(b":")
            if len(parts) == 2:
                to, amount = parts
                try:
                    to = int(to)
                    amount = int(amount)
                except ValueError:
                    continue
                transfers.append((to, amount))
        assert sum(amount for _, amount in transfers) <= from_acc.spacebucks
        for to, amount in transfers:
            from_acc.spacebucks -= amount
            self.secrets.accounts[to].spacebucks += amount

    def get_balance(self, id_):
        return self.secrets.accounts[id_].spacebucks


class BankServer:
    """What would be the web API."""

    class ClientSession:

        def __init__(self, from_id, key):
            self.from_id = from_id
            self._key = key

        def transfer_v1(self, to_id, amount, api):
            msg = f"from={self.from_id}&to={to_id}&amount={amount}"
            msg = msg.encode("ascii")
            iv = random_helper.random_bytes(16)
            mac_ = mac.cbc_mac(self._key, msg, iv)
            api.transfer_v1(msg + iv + mac_)

        def transfer_v2(self, txns, api):
            msg = f"from={self.from_id}&tx_list="
            msg += ";".join(f"{to}:{amount}" for to, amount in txns)
            msg = msg.encode("ascii")
            mac_ = mac.cbc_mac(self._key, msg)
            api.transfer_v2(msg + mac_)

    def __init__(self, secrets):
        self.secrets = secrets

    def login(self, name, password) -> ClientSession:
        from_id = next(acc.id_ for acc in self.secrets.accounts.values()
                       if acc.name == name and acc.password == password)
        return BankServer.ClientSession(from_id, self.secrets.key)


def reset():
    secrets = Secrets()
    api = BankApi(secrets)
    server = BankServer(secrets)
    alice = server.login("Alice", "@l1c3!")  # We don't see that!
    me = server.login("Mallory", "hunter2")
    return api, server, alice, me


# Test our regular bank logic.
api, _, alice, me = reset()
assert api.get_balance(id_=0) == 1000500
assert api.get_balance(id_=1) == 100
alice.transfer_v1(to_id=1, amount=500, api=api)
assert api.get_balance(id_=0) == 1000000
assert api.get_balance(id_=1) == 600
# Can't do transfers without knowing the key.
try:
    bad_client = BankServer.ClientSession(from_id=0, key=b"1234123412341234")
    bad_client.transfer_v1(to_id=0, amount=500, api=api)
    assert False, "accepted a bad transaction"
except ValueError:
    pass
# Let's reset:
api, bank, _, me = reset()


# Create a MitM bank API:
class MitmApi:
    def __init__(self):
        self._intercepted = None

    def transfer_v1(self, msg):
        self._intercepted = msg

    def transfer_v2(self, msg):
        self._intercepted = msg

    def read(self):
        ret = self._intercepted
        self._intercepted = None
        return ret


# CBC encryption will do: `AES_k(pt ^ iv)` for the first block. So we can
# manipulate it by ensuring that bitflips we make on pt are also done on iv,
# then we get the same final CBC-MAC.
mitm = MitmApi()

print("Getting rich with protocol V1.")
while api.get_balance(id_=2) < 1000000:  # While we're not rich...
    amount = api.get_balance(id_=2)
    amount = min(amount, api.get_balance(id_=0))  # Max we can steal
    # Make a transfer to myself to get an example transaction:
    me.transfer_v1(to_id=2, amount=amount, api=mitm)
    msg = mitm.read()
    mac_ = msg[-16:]
    iv = msg[-32:-16]
    msg = msg[:-32]
    # Looks like: from=2&to=2&amount=XYZ
    #             |||||||||||||||| (first block)
    # We want:    from=0&to=2&amou
    first_block = msg[:16]
    target = b"from=0&to=2&amou"
    assert len(target) == 16
    xors = xor.xor_bytes(first_block, target)
    iv = xor.xor_bytes(iv, xors)
    api.transfer_v1(target + msg[16:] + iv + mac_)
    print(f"We now have: {api.get_balance(id_=2)}$!")


# V2 now has a fixed IV.
api, bank, alice, me = reset()

# Test bank logic:
alice.transfer_v2(txns=[(1, 500), (1, 1000)], api=api)
assert api.get_balance(id_=1) == 1600
try:  # Make sure MAC is checked
    bad_client = BankServer.ClientSession(from_id=0, key=b"1234123412341234")
    bad_client.transfer_v2(txns=[(1, 500), (1, 1000)], api=api)
    assert False, "accepted a bad transaction"
except ValueError:
    pass

# # Let's reset:
api, bank, alice, me = reset()

# We have the last ciphertext block of Alice's message (the MAC).
# We have the MAC of one of our messages.
# By xoring our first plaintext block, we can chain our message to Alice's in a
# way that will match the IV=0 behavior, allowing us to get our same final MAC.

print("Getting rich with protocol V2.")
# Intercept a transaction from Alice:
alice.transfer_v2(txns=[(1, 1)], api=mitm)
msg = mitm.read()
alice_msg, alice_mac = msg[:-16], msg[-16:]
api.transfer_v2(msg)  # Do the real transaction to hide our mitm.
while api.get_balance(id_=2) < 1000000:  # While we're not rich...
    amount = api.get_balance(id_=2)
    # Max we can steal (-1 because Alice is transfering $1 to Bob)
    amount = min(amount, api.get_balance(id_=0) - 1)
    # Make a transfer to myself to get an example transaction.
    # Our first block will get scrambled, so we want to be strategic in what
    # shows up in the second block:
    #   from=2&tx_list=2:0;2:XYZ;
    #   ||||||||||||||||----------------
    # We want to make sure we include a ';' separator, so send 2 transactions.
    me.transfer_v2(txns=[(2, 0), (2, amount)], api=mitm)
    msg = mitm.read()
    me_msg, me_mac = msg[:-16], msg[-16:]
    first_block, rest = me_msg[:16], me_msg[16:]
    target_iv = b"\x00" * 16
    first_block = xor.xor_bytes(first_block,
                                xor.xor_bytes(target_iv, alice_mac))
    api.transfer_v2(aes.pad(alice_msg) + first_block + rest + me_mac)
    print(f"We now have: {api.get_balance(id_=2)}$!")
