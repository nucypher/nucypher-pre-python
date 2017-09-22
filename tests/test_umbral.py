from npre import umbral


def test_encrypt_decrypt():
    pre = umbral.PRE()
    priv_key = pre.gen_priv()
    pub_key = pre.priv2pub(priv_key)

    sym_key, ekey = pre.encapsulate(pub_key)
    assert len(sym_key) == 32

    # The symmetric key sym_key should be used for block cipher

    sym_key_2 = pre.decapsulate(priv_key, ekey)
    assert sym_key_2 == sym_key


def test_reencrypt():
    pre = umbral.PRE()
    priv_alice = pre.gen_priv()
    pub_alice = pre.priv2pub(priv_alice)
    priv_bob = pre.gen_priv()

    sym_key, ekey_alice = pre.encapsulate(pub_alice)

    rk_ab = pre.rekey(priv_alice, priv_bob)

    ekey_bob = pre.reencrypt(rk_ab, ekey_alice)

    sym_key_2 = pre.decapsulate(priv_bob, ekey_bob)
    assert sym_key_2 == sym_key

    sym_key_3 = pre.decapsulate(priv_bob, ekey_alice)
    assert sym_key_3 != sym_key
