from .. import dh


class ParamsMitm(dh.DhClient):

    def __init__(self, server, p, g):
        super().__init__(g, p)
        self.initiate_dh(server)

    def predict_s(self, predicted_s):
        assert predicted_s == self._s


server = dh.DhServer()
p = dh.MODP_PRIME_1536


# With g=1:
# s = g^a^b mod p = 1^a^b mod p = 1 mod p
ParamsMitm(server, p, g=1).predict_s(1)

# With g=p:
# s = g^a^b mod p
#   = p^a^b mod p
#   = 0 mod p
ParamsMitm(server, p, g=p).predict_s(0)
# Note that it's the same for g=0.
ParamsMitm(server, p, g=0).predict_s(0)

# With g=p-1:
# s = g^a^b mod p
#   = (p-1)^a^b mod p
#   = -1 ^ a ^ b mod p
#   = { 1 if a*b is even
#     { -1 if a*b is odd
mitm = ParamsMitm(server, p, g=p-1)
# We can know if 'a'&'b' were even or odd in a similar way:
a_odd = mitm.A == p-1
b_odd = mitm.B == p-1
ab_odd = a_odd and b_odd
mitm.predict_s(p-1 if ab_odd else 1)
