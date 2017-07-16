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
