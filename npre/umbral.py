'''
Umbral: split-key proxy re-encryption for ECIES
'''

import npre.elliptic_curve as ec
from npre import curves
from npre.constants import UNKNOWN_KFRAG
from typing import Union
from sha3 import keccak_256 as keccak
from collections import namedtuple
from functools import reduce
from operator import mul
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


EncryptedKey = namedtuple('EncryptedKey', ['ekey', 're_id'])

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

    def kdf(self, ecdata, key_length):
        # XXX length
        ecdata = ec.serialize(ecdata)[1:]  # Remove the first (type) bit

        # TODO: Handle salt somehow
        return HKDF(
            algorithm=hashes.SHA512(),
            length=key_length,
            salt=None,
            info=None,
            backend=default_backend()
        ).derive(ecdata)

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
        return RekeyFrag(id=None, key=rk, pre=self)

    def split_rekey(self, priv_a, priv_b, threshold, N):
        coeffs = [priv_a * (~priv_b)]  # Standard rekey
        coeffs += [ec.random(self.ecgroup, ec.ZR) for _ in range(threshold - 1)]

        ids = [ec.random(self.ecgroup, ec.ZR) for _ in range(N)]
        rk_shares = [
                RekeyFrag(id, key=poly_eval(coeffs, id), pre=self)
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

    def encapsulate(self, pub_key, key_length=32):
        """Generare an ephemeral key pair and symmetric key"""
        priv_e = ec.random(self.ecgroup, ec.ZR)
        pub_e = self.g ** priv_e

        # DH between eph_private_key and public_key
        shared_key = pub_key ** priv_e

        # Key to be used for symmetric encryption
        key = self.kdf(shared_key, key_length)

        return key, EncryptedKey(pub_e, re_id=None)

    def decapsulate(self, priv_key, ekey, key_length=32):
        """Derive the same symmetric key"""
        shared_key = ekey.ekey ** priv_key
        key = self.kdf(shared_key, key_length)
        return key


class RekeyFrag(object):

    _pre = PRE()

    def __init__(self, id, key, pre=None):
        self.id = id
        self.key = key
        if pre is None:
            pre = self._pre
        self.pre = pre

    def __bytes__(self):
        return ec.serialize(self.id) + ec.serialize(self.key)

    def __eq__(self, other_kfrag):
        if other_kfrag is UNKNOWN_KFRAG:
            return False
        return bytes(self) == bytes(other_kfrag)

    @classmethod
    def from_bytes(cls, kfrag_bytes, pre=None):
        pre = pre or cls._pre
        return RekeyFrag(id=ec.deserialize(pre.ecgroup, kfrag_bytes[:len(kfrag_bytes) // 2]),
                         key=ec.deserialize(pre.ecgroup, kfrag_bytes[len(kfrag_bytes) // 2:]),
                         pre=pre)
