from npre.elliptic_curve import G, elliptic_curve
from npre.elliptic_curve import random as group_random
from npre import curves


class PRE(object):
    def __init__(self, curve=curves.secp256k1, g=None):
        self.curve = curves.secp256k1
        self.ecgroup = elliptic_curve(nid=self.curve)
        if g is None:
            self.g = group_random(self.ecgroup, G)  # XXX load??
