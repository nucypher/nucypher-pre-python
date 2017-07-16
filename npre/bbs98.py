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
