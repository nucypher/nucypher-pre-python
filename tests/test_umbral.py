from npre import umbral


def test_encrypt_decrypt():
    pre = umbral.PRE()
    priv_key = pre.gen_priv()
    pub_key = pre.priv2pub(priv_key)

    sym_key, ekey = pre.encapsulate(pub_key)
    assert len(sym_key) == 32

    sym_key_2 = pre.decapsulate(priv_key, ekey)
    assert sym_key_2 == sym_key
