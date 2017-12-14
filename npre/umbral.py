'''
Umbral -- A Threshold Proxy Re-Encryption based on ECIES-KEM and BBS98

Implemented by:
David Nuñez (dnunez@lcc.uma.es);
Michael Egorov (michael@nucypher.com)

TODO: 
    * input validation on all methods
    * generator h for vKeys
    * full-domain hash

'''

import npre.elliptic_curve as ec
from npre import curves
from typing import Union
from collections import namedtuple
from functools import reduce
from operator import mul
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


EncryptedKey = namedtuple('EncryptedKey', ['ekey', 'vcomp', 'scomp'])
ReEncryptedKey = namedtuple('ReEncryptedKey', ['ekey', 'vcomp', 're_id'])
ReCombined = namedtuple('ReCombined', ['ekey', 'vcomp'])

RekeyFrag = namedtuple('RekeyFrag', ['id', 'key'])


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
        self.order = ec.order(self.ecgroup)

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

    def hash_points_to_bn(self, list):

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        for point in list:
            digest.update(ec.serialize(point))
        hash = digest.finalize()
        h = int.from_bytes(hash, byteorder='big', signed=False) % self.order

        return h

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

        # TODO: change this!
        h = self.g

        vKeys = [h ** coeff for coeff in coeffs]

        ids = [ec.random(self.ecgroup, ec.ZR) for _ in range(N)]
        rk_shares = [
                RekeyFrag(id, key=poly_eval(coeffs, id))
                for id in ids]

        return rk_shares, vKeys

    def check_kFrag_consistency(self, kFrag, vKeys):
        if vKeys is None or len(vKeys) == 0:
            raise ValueError('vKeys must not be empty')

        i = kFrag.id
        # TODO: change this!
        h = self.g
        lh_exp = h ** kFrag.key

        if len(vKeys) > 1:
            i_j = [i]
            for _ in range(len(vKeys) - 2):
                i_j.append(i_j[-1] * i)
            rh_exp = reduce(mul, [x ** y for (x, y) in zip(vKeys[1:], i_j)])
            rh_exp = vKeys[0] * rh_exp

        else:
            rh_exp = vKeys[0]

        return lh_exp == rh_exp

    def combine(self, reencrypted_keys):
        x0 = reencrypted_keys[0]
        
        if len(reencrypted_keys) > 1:
            ids = [x.re_id for x in reencrypted_keys]
            lambda_0 = lambda_coeff(x0.re_id, ids)
            e = x0.ekey ** lambda_0
            v = x0.vcomp ** lambda_0
            for x in reencrypted_keys[1:]:
                lambda_i = lambda_coeff(x.re_id, ids)
                e = e * (x.ekey  ** lambda_i)
                v = v * (x.vcomp ** lambda_i)

            return ReCombined(ekey=e, vcomp=v)

        else: #if len(reencrypted_keys) == 1:
            return ReCombined(ekey=x0.ekey, vcomp=x0.vcomp)

    def reencrypt(self, rk, encrypted_key):

        e = encrypted_key.ekey
        v = encrypted_key.vcomp
        s = encrypted_key.scomp
        h = self.hash_points_to_bn([e, v])

        e1 = e ** rk.key
        v1 = v ** rk.key

        # Check after performing the operations to avoid timing oracles
        assert self.g ** s == v * (e ** h), "Generic Umbral Error"

        return ReEncryptedKey(ekey=e1, vcomp=v1, re_id=rk.id)

    def encapsulate(self, pub_key, key_length=32):
        """Generare an ephemeral key pair and symmetric key"""
        
        priv_r = ec.random(self.ecgroup, ec.ZR)
        pub_r = self.g ** priv_r

        priv_u = ec.random(self.ecgroup, ec.ZR)
        pub_u = self.g ** priv_u

        h = self.hash_points_to_bn([pub_r, pub_u])
        s = priv_u + priv_r * h

        # DH between eph_private_key and public_key
        shared_key = pub_key ** priv_r

        # Key to be used for symmetric encryption
        key = self.kdf(shared_key, key_length)

        return key, EncryptedKey(ekey=pub_r, vcomp=pub_u, scomp=s)

    def decapsulate_original(self, priv_key, encrypted_key, key_length=32):
        """Derive the same symmetric key"""
        shared_key = encrypted_key.ekey ** priv_key
        key = self.kdf(shared_key, key_length)
        return key

    def decapsulate_reencrypted(self, priv_key, reencrypted_key, orig_pk, orig_encrypted_key, key_length=32):
        """Derive the same symmetric key"""

        e1 = reencrypted_key.ekey
        v1 = reencrypted_key.vcomp

        shared_key = e1 ** priv_key
        key = self.kdf(shared_key, key_length)

        e = orig_encrypted_key.ekey
        v = orig_encrypted_key.vcomp
        s = orig_encrypted_key.scomp
        h = self.hash_points_to_bn([e, v])

        inv_b = ~priv_key

        assert orig_pk ** (s * inv_b) == v1 * (e1 ** h), "Generic Umbral Error"

        return key

