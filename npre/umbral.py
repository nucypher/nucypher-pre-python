'''
Umbral: split-key proxy re-encryption for ECIES
'''

import npre.elliptic_curve as ec
from npre import curves
from typing import Union
from sha3 import keccak_256 as keccak
from collections import namedtuple
from functools import reduce
from operator import mul


EncryptedKey = namedtuple('EncryptedKey', ['ekey', 're_id'])


class RekeyFrag(object):
    """
    Represents a fragment of a Re-encryption key.
    """

    def __init__(self, id, key):
        self.id = id
        self.key = key

    def __bytes__(self):
        id = int(self.id).to_bytes(32, 'big')
        key = int(self.key).to_bytes(32, 'big')
        return id + key

    def __eq__(self, other_kfrag):
        return self.id == other_kfrag.id and self.key == other_kfrag.key

    @classmethod
    def from_bytes(cls, kfrag_bytes):
        id = int.from_bytes(kfrag_bytes[:32], 'big')
        key = int.from_bytes(kfrag_bytes[32:], 'big')
        return RekeyFrag(id, key)

    @classmethod
    def to_bytes(cls, kfrag):
        return bytes(kfrag)


# XXX serialization probably should be done through decorators
# XXX write tests


def lambda_coeff(id_i, selected_ids):
    filtered_list = [x for x in selected_ids if x != id_i]
    map_list = [id_j * ~(id_j - id_i) for id_j in filtered_list]
    x = reduce(mul, map_list)
    return x


def poly_eval(coeff, x):
    result = coeff[-1]
    for i in range(-2, -len(coeff) - 1, - 1):
        result = result * x + coeff[i]
    return result


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

    def split_rekey(self, priv_a, priv_b, threshold, N):
        coeffs = [priv_a * (~priv_b)]  # Standard rekey
        coeffs += [ec.random(self.ecgroup, ec.ZR) for _ in range(threshold - 1)]

        ids = [ec.random(self.ecgroup, ec.ZR) for _ in range(N)]
        rk_shares = [
                RekeyFrag(id, key=poly_eval(coeffs, id))
                for id in ids]

        return rk_shares

    def combine(self, encrypted_keys):
        if len(encrypted_keys) > 1:
            ids = [x.re_id for x in encrypted_keys]
            map_list = [
                    x.ekey ** lambda_coeff(x.re_id, ids)
                    for x in encrypted_keys]
            product = reduce(mul, map_list)
            return EncryptedKey(ekey=product, re_id=None)

        elif len(encrypted_keys) == 1:
            return encrypted_keys[0]

    def reencrypt(self, rk, ekey):
        new_ekey = ekey.ekey ** rk.key
        return EncryptedKey(new_ekey, rk.id)

    def encapsulate(self, pub_key):
        """Generare an ephemeral key pair and symmetric key"""
        priv_e = ec.random(self.ecgroup, ec.ZR)
        pub_e = self.g ** priv_e

        # DH between eph_private_key and public_key
        shared_key = pub_key ** priv_e

        # Key to be used for symmetric encryption
        key = self.kdf(shared_key)

        return key, EncryptedKey(pub_e, re_id=None)

    def decapsulate(self, priv_key, ekey):
        """Derive the same symmetric key"""
        shared_key = ekey.ekey ** priv_key
        key = self.kdf(shared_key)
        return key
