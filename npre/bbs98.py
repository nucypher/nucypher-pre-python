from pyelliptic.openssl import curves

ZR=0
G=1


class PRE(object):
    def __init__(self, curve='secp256k1', g=None):
        self.curve = curves[curve]
        if g is None:
            self.g = group_random(G)
