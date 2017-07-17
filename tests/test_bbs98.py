from npre import bbs98


def test_serde():
    pre = bbs98.PRE()
    pre1 = bbs98.PRE(**pre.to_dict())

    assert pre.g == pre1.g
    assert pre.curve == pre1.curve

    s = pre.serialize()
    pre2 = bbs98.PRE.deserialize(s)

    assert pre.g == pre2.g
    assert pre.curve == pre2.curve


def test_keyops():
    pre = bbs98.PRE()

    # Check types
    priv = pre.gen_priv(dtype=bytes)
    assert type(priv) is bytes
    pub = pre.priv2pub(priv)
    assert type(pub) is bytes

    # Check types
    priv2 = pre.gen_priv()
    assert priv2 is not None
    assert type(priv2) is not bytes
    pub2 = pre.priv2pub(priv2)
    assert pub2 is not None
    assert type(pub2) is not bytes

    # Check serialization
    assert priv == pre.save_key(pre.load_key(priv))
    assert pub == pre.save_key(pre.load_key(pub))
    assert pre.load_key(pre.save_key(priv2)) == priv2
    assert pre.load_key(pre.save_key(pub2)) == pub2

    # Check that RNG gave us different keys
    assert priv != pre.save_key(priv2)
    assert pub != pre.save_key(pub2)

    # Check that creating a new PRE object with same params gives the same key
    pre2 = bbs98.PRE.deserialize(pre.serialize())
    pub3 = pre2.priv2pub(priv)
    assert pub3 == pub
