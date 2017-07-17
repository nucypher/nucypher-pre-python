from npre.util import pad, unpad


def test_pad():
    msg = b'Hello crypto'
    l = 30
    msgpad = pad(l, msg)
    assert len(msgpad) == l
    assert unpad(msgpad) == msg
