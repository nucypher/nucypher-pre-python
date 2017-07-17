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
