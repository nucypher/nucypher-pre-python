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
from npre.util import pad, unpad
import msgpack


class PRE(object):
    def __init__(self, curve=curves.secp256k1, g=None):
        self.curve = curves.secp256k1
        self.ecgroup = ec.elliptic_curve(nid=self.curve)
        if g is None:
            self.g = ec.random(self.ecgroup, ec.G)
        else:
            self.g = ec.deserialize(self.ecgroup, g)
        self.bitsize = ec.bitsize(self.ecgroup)

    def to_dict(self):
        return {'g': ec.serialize(self.g),
                'curve': self.curve}

    def serialize(self):
        return msgpack.dumps(self.to_dict())

    @classmethod
    def deserialize(cls, s):
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
        if type(key) is bytes:
            return ec.deserialize(self.ecgroup, key)
        else:
            return key

    def save_key(self, key):
        return ec.serialize(key)

    def encrypt(self, pub, msg, padding=True):
        if type(msg) is str:
            msg = msg.encode()
        if padding:
            msg = pad(self.bitsize, msg)
        m = ec.encode(self.ecgroup, msg, False)
        r = ec.random(self.ecgroup, ec.ZR)
        c1 = self.load_key(pub) ** r
        c2 = (self.g ** r) * m
        return msgpack.dumps([ec.serialize(c1), ec.serialize(c2)])

    def decrypt(self, priv, emsg, padding=True):
        if type(emsg) is str:
            emsg = emsg.encode()
        c1, c2 = [self.load_key(x) for x in msgpack.loads(emsg)]
        m = c2 / (c1 ** (~self.load_key(priv)))
        msg = ec.decode(self.ecgroup, m, False)
        if padding:
            return unpad(msg)
        else:
            return msg

    def rekey(self, priv1, priv2, dtype=None):
        if dtype is None:
            dtype = type(priv1)
        priv1 = self.load_key(priv1)
        priv2 = self.load_key(priv2)
        rk = priv2 * (~priv1)
        if dtype in (bytes, 'bytes'):
            return self.save_key(rk)
        else:
            return rk

    def reencrypt(self, rk, emsg):
        if type(emsg) is str:
            emsg = emsg.encode()
        rk = self.load_key(rk)
        c1, c2 = [self.load_key(x) for x in msgpack.loads(emsg)]
        c1 = c1 ** rk
        return msgpack.dumps([ec.serialize(c1), ec.serialize(c2)])
