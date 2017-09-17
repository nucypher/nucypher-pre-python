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
from typing import Union


class PRE(object):
    def __init__(self, curve=curves.secp256k1, g=None):
        self.curve = curve
        self.ecgroup = ec.elliptic_curve(nid=self.curve)

        if g is None:
            self.g = ec.getGenerator(self.ecgroup)
        else:
            if isinstance(g, ec.ec_element):
                self.g = g
            else:
                self.g = ec.deserialize(self.ecgroup, g)

        self.bitsize = ec.bitsize(self.ecgroup)

    def gen_priv(self, dtype='ec'):
        priv = ec.random(self.ecgroup, ec.ZR)
        if dtype in ('bytes', bytes):
            return ec.serialize(priv)
        else:
            return priv

    def priv2pub(self, priv: Union[bytes, 'elliptic_curve.Element']):
        """
        Takes priv, a secret bytes or elliptic_curve.Element object to be used as a private key.
        Derives a matching public key and returns it.

        Returns a public key matching the type of priv.
        """
        if type(priv) is bytes:
            # If priv is a bytes object, we need to "deserialize" it to an Element first,
            # then raise g to its power, then "reserialize" it to bytes.
            priv = ec.deserialize(self.ecgroup, priv)
            pub = self.g ** priv
            return ec.serialize(pub)
        else:
            pub = self.g ** priv
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
            chunks = [
                    msg[i * self.bitsize: i * self.bitsize + self.bitsize]
                    for i in range(len(msg) // self.bitsize)]
        else:
            chunks = [msg]
        r = ec.random(self.ecgroup, ec.ZR)
        c1 = self.load_key(pub) ** r
        c2 = [(self.g ** r) * ec.encode(self.ecgroup, m, False) for m in chunks]
        c2 = map(ec.serialize, c2)
        return msgpack.dumps([ec.serialize(c1)] + list(c2))

    def decrypt(self, priv, emsg, padding=True):
        if type(emsg) is str:
            emsg = emsg.encode()
        emsg = [self.load_key(m) for m in msgpack.loads(emsg)]
        c1 = emsg[0]
        c2 = emsg[1:]
        p = c1 ** (~self.load_key(priv))
        m = [c / p for c in c2]
        msg = [ec.decode(self.ecgroup, m_i, False) for m_i in m]
        if padding:
            return b''.join(msg[:-1] + [unpad(msg[-1])])
        else:
            return msg[0]

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
        emsg = msgpack.loads(emsg)
        c1 = self.load_key(emsg[0])
        c1 = c1 ** rk
        return msgpack.dumps([ec.serialize(c1)] + emsg[1:])
