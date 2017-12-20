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
ReEncryptedKey = namedtuple('ReEncryptedKey', ['ekey', 'vcomp', 're_id', 'xcomp'])
ReCombined = namedtuple('ReCombined', ['ekey', 'vcomp', 'xcomp', 'u1', 'z1', 'z2'])
ChallengeResponse = namedtuple('ChallengeResponse', ['e2', 'v2', 'u1', 'u2', 'z1', 'z2', 'z3'])

RekeyFrag = namedtuple('RekeyFrag', ['id', 'key', 'xcomp', 'u1', 'z1', 'z2'])


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
        priv = ec.random(self.ecgroup, ec.ZR)
        return priv

    def priv2pub(self, priv: Union[bytes, 'elliptic_curve.Element']):
        """
        Takes priv, a secret bytes or elliptic_curve.Element object to be used as a private key.
        Derives a matching public key and returns it.

        Returns a public key matching the type of priv.
        """
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

    def split_rekey(self, priv_a, pub_b, threshold, N):

        x = ec.random(self.ecgroup, ec.ZR)
        xcomp = self.g ** x
        d = self.hash_points_to_bn([xcomp, pub_b, pub_b ** x])
        # print([xcomp, pub_b, pub_b ** x])
        # print(d)

        coeffs = [priv_a * (~d)]  # Standard rekey
        coeffs += [ec.random(self.ecgroup, ec.ZR) for _ in range(threshold - 1)]

        # TODO: change this into public parameters different than g
        h = self.g
        u = self.g

        vKeys = [h ** coeff for coeff in coeffs]

        rk_shares = []
        for _ in range(N):
            id = ec.random(self.ecgroup, ec.ZR)
            rk = poly_eval(coeffs, id)

            u1 = u ** rk
            y  = ec.random(self.ecgroup, ec.ZR)

            z1 = self.hash_points_to_bn([xcomp, u1, self.g ** y])
            z2 = y - priv_a * z1

            kFrag = RekeyFrag(id=id, key=rk, xcomp=xcomp, u1=u1, z1=z1, z2=z2)
            rk_shares.append(kFrag)

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
        re0, ch0 = reencrypted_keys[0]
        
        if len(reencrypted_keys) > 1:
            ids = [re.re_id for re,_ in reencrypted_keys]
            lambda_0 = lambda_coeff(re0.re_id, ids)
            e = re0.ekey ** lambda_0
            v = re0.vcomp ** lambda_0
            for re,_ in reencrypted_keys[1:]:
                lambda_i = lambda_coeff(re.re_id, ids)
                e = e * (re.ekey  ** lambda_i)
                v = v * (re.vcomp ** lambda_i)

            return ReCombined(ekey=e, vcomp=v, xcomp=re0.xcomp, u1=ch0.u1, z1=ch0.z1, z2=ch0.z2)

        else: #if len(reencrypted_keys) == 1:
            return ReCombined(ekey=re0.ekey, vcomp=re0.vcomp, xcomp=re0.xcomp, u1=ch0.u1, z1=ch0.z1, z2=ch0.z2)

    def reencrypt(self, rk, encrypted_key):

        ## ReEncryption:

        e = encrypted_key.ekey
        v = encrypted_key.vcomp
        s = encrypted_key.scomp
        h = self.hash_points_to_bn([e, v])

        e1 = e ** rk.key
        v1 = v ** rk.key

        # Check after performing the operations to avoid timing oracles
        assert self.g ** s == v * (e ** h), "Generic Umbral Error"

        reenc = ReEncryptedKey(ekey=e1, vcomp=v1, re_id=rk.id, xcomp=rk.xcomp)

        ## Challenge:

        # TODO: change this into a public parameter different than g
        u = self.g
        u1 = rk.u1

        t = ec.random(self.ecgroup, ec.ZR)
        e_t = e ** t
        v_t = v ** t
        u_t = u ** t

        h = self.hash_points_to_bn([e, e1, e_t, v, v1, v_t, u, u1, u_t])
        print(h)
        # print("REENCRYPT")
        # for jarl in [e, e1, e_t, v, v1, v_t, u, u1, u_t]:
        #     print(jarl)
        # print("")

        z3 = t + h*rk.key

        ch_resp = ChallengeResponse(e2=e_t, v2=v_t, u1=u1, u2=u_t, z1=rk.z1, z2=rk.z2, z3=z3)
        return reenc, ch_resp

    def check_challenge(self, encrypted_key, reencrypted_key, challenge_resp, pub_a):
        e = encrypted_key.ekey
        v = encrypted_key.vcomp
        

        e1 = reencrypted_key.ekey
        v1 = reencrypted_key.vcomp
        xcomp = reencrypted_key.xcomp

        e2 = challenge_resp.e2
        v2 = challenge_resp.v2

        # TODO: change this into a public parameter different than g
        u = self.g
        u1 = challenge_resp.u1
        u2 = challenge_resp.u2

        z1 = challenge_resp.z1
        z2 = challenge_resp.z2
        z3 = challenge_resp.z3

        ycomp = (self.g ** z2) * (pub_a ** z1)

        h = self.hash_points_to_bn([e, e1, e2, v, v1, v2, u, u1, u2])
        print(h)
        # print("ch")
        # for jarl in [e, e1, e2, v, v1, v2, u, u1, u2]:
        #     print(jarl)
        # print("")
        check31 = z1 == self.hash_points_to_bn([xcomp, u1, ycomp])
        check32 = e ** z3 == e2 * (e1 ** h)
        check33 = u ** z3 == u2 * (u1 ** h)

        #assert check31
        #assert check32
        #assert check33

        return check31 & check32 & check33

    def encapsulate(self, pub_key, key_length=32):
        """Generare an ephemeral key pair and symmetric key"""
        
        priv_r = ec.random(self.ecgroup, ec.ZR)
        pub_r = self.g ** priv_r

        priv_u = ec.random(self.ecgroup, ec.ZR)
        pub_u = self.g ** priv_u

        h = self.hash_points_to_bn([pub_r, pub_u])
        s = priv_u + priv_r * h

        shared_key = pub_key ** (priv_r + priv_u)

        # Key to be used for symmetric encryption
        key = self.kdf(shared_key, key_length)

        return key, EncryptedKey(ekey=pub_r, vcomp=pub_u, scomp=s)

    def decapsulate_original(self, priv_key, encrypted_key, key_length=32):
        """Derive the same symmetric key"""

        shared_key = (encrypted_key.ekey * encrypted_key.vcomp) ** priv_key
        key = self.kdf(shared_key, key_length)
        return key

    def decapsulate_reencrypted(self, pub_key, priv_key, recombined_key, orig_pk, orig_encrypted_key, key_length=32):
        """Derive the same symmetric key"""

        xcomp = recombined_key.xcomp
        d = self.hash_points_to_bn([xcomp, pub_key, xcomp ** priv_key])

        e1 = recombined_key.ekey
        v1 = recombined_key.vcomp
        
        shared_key = (e1 * v1) ** d
        key = self.kdf(shared_key, key_length)

        e = orig_encrypted_key.ekey
        v = orig_encrypted_key.vcomp
        s = orig_encrypted_key.scomp
        h = self.hash_points_to_bn([e, v])
        inv_d = ~d
        assert orig_pk ** (s * inv_d) == v1 * (e1 ** h), "Generic Umbral Error"

        return key

