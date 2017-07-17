'''
BBS Proxy Re-Encryption
| From: Blaze, M., Bleumer, G., & Strauss, M. (1998). Divertible protocols and atomic proxy cryptography.
| Published in: Advances in Cryptology-EUROCRYPT'98 (pp. 127-144). Springer Berlin Heidelberg.
| Available from: http://link.springer.com/chapter/10.1007/BFb0054122
* type:           proxy encryption
* properties:     CPA-secure, bidirectional, multihop, not collusion-resistant, interactive, transitive
* setting:        DDH-hard EC groups of prime order (F_p) or Integer Groups
* assumption:     DDH

This is private-private reencryption, so reencrypting to a public key requires creating an ephemeral random key

Inspired by Charm's bbs98
D. Nuñez (dnunez@lcc.uma.es); 04/2016

Implemented by:
M. Egorov (michael@nucypher.com); 06/2017
'''

import npre.elliptic_curve as ec
from npre import curves


class PRE(object):
    def __init__(self, curve=curves.secp256k1, g=None):
        self.curve = curves.secp256k1
        self.ecgroup = ec.elliptic_curve(nid=self.curve)
        if g is None:
            self.g = ec.random(self.ecgroup, ec.G)
        else:
            self.g = ec.deserialize(self.ecgroup, g)

    def to_dict(self):
        return {'g': ec.serialize(self.g),
                'curve': self.curve}

    def serialize(self):
        import msgpack
        return msgpack.dumps(self.to_dict())

    @classmethod
    def deserialize(cls, s):
        import msgpack
        d = msgpack.loads(s)
        return cls(**{x.decode(): d[x] for x in d})

    def gen_priv(self, dtype='ec'):
        priv = ec.random(self.ecgroup, ec.ZR)
        if dtype in ('bytes', bytes):
            return ec.serialize(priv)
        else:
            return priv

    def priv2pub(self, priv):
        dtype = 'ec'
        if type(priv) is str:
            priv = priv.encode()
        if type(priv) is bytes:
            dtype = bytes
            priv = ec.deserialize(self.ecgroup, priv)
        pub = self.g ** priv
        if dtype is bytes:
            return ec.serialize(pub)
        else:
            return pub

    def load_key(self, key):
        return ec.deserialize(self.ecgroup, key)

    def save_key(self, key):
        return ec.serialize(key)

    def encrypt(self, pub, msg):
        pass

    def decrypt(self, priv, msg):
        pass

    def rekey(self, priv, pub, dtype='ec'):
        pass

    def reencrypt(self, rk, msg):
        pass
