'''
Umbral: split-key proxy re-encryption for ECIES
'''

import npre.elliptic_curve as ec
from npre import curves
from typing import Union
from sha3 import keccak_256 as keccak
from collections import namedtuple


EncryptedKey = namedtuple('EncryptedKey', ['ekey', 're_id'])
RekeyFrag = namedtuple('RekeyFrag', ['id', 'key'])

# XXX for readability, made all the types non-serialized (EC, tuples)
# XXX serialization probably should be done through decorators


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

    def kdf(self, ecdata):
        # XXX length
        for_hash = ec.serialize(ecdata)[1:]  # Remove the first (type) bit
        return keccak(for_hash).digest()

    def gen_priv(self, dtype='ec'):
        # Same as in BBS98
        priv = ec.random(self.ecgroup, ec.ZR)
        return priv

    def priv2pub(self, priv: Union[bytes, 'elliptic_curve.Element']):
        """
        Takes priv, a secret bytes or elliptic_curve.Element object to be used as a private key.
        Derives a matching public key and returns it.

        Returns a public key matching the type of priv.
        """
        # Same as in BBS98
        pub = self.g ** priv
        return pub

    def load_key(self, key):
        # Same as in BBS98
        if type(key) is bytes:
            return ec.deserialize(self.ecgroup, key)
        else:
            return key

    def save_key(self, key):
        # Same as in BBS98
        return ec.serialize(key)

    def rekey(self, priv1, priv2, dtype=None):
        # Same as in BBS98
        rk = priv1 * (~priv2)
        return RekeyFrag(id=None, key=rk)

    # XXX split_rekey
    # XXX combine
    # XXX lambda_coeff
    # XXX poly_eval

    def reencrypt(self, rk, ekey):
        new_ekey = ekey.ekey ** rk.key
        return EncryptedKey(new_ekey, rk.id)

    def encapsulate(self, pub_key):
        """Generare an ephemeral key pair and symmetric key"""
        priv_e = self.ecgroup.random()
        pub_e = self.g ** priv_e

        # DH between eph_private_key and public_key
        shared_key = pub_key ** priv_e

        # Key to be used for symmetric encryption
        key = self.kdf(self.ecgroup.serialize(shared_key)[1:])

        return key, EncryptedKey(pub_e, re_id=None)

    def decapsulate(self, priv_key, ekey):
        """Derive the same symmetric key"""
        shared_key = ekey.ekey ** priv_key
        key = self.kdf(shared_key)
        return key
