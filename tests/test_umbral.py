import pytest
import random
from npre import umbral
import npre.elliptic_curve as ec


def test_encrypt_decrypt():
    pre = umbral.PRE()
    priv_key = pre.gen_priv()
    pub_key = pre.priv2pub(priv_key)

    sym_key, ekey = pre.encapsulate(pub_key)
    assert len(sym_key) == 32

    # The symmetric key sym_key should be used for block cipher

    sym_key_2 = pre.decapsulate_original(priv_key, ekey)
    assert sym_key_2 == sym_key


def test_reencrypt():
    pre = umbral.PRE()
    priv_alice = pre.gen_priv()
    pub_alice = pre.priv2pub(priv_alice)
    priv_bob = pre.gen_priv()

    sym_key, ekey_alice = pre.encapsulate(pub_alice)

    rk_ab = pre.rekey(priv_alice, priv_bob)

    ekey_bob = pre.reencrypt(rk_ab, ekey_alice)

    sym_key_2 = pre.decapsulate_reencrypted(priv_bob, ekey_bob, pub_alice, ekey_alice)
    assert sym_key_2 == sym_key

    sym_key_3 = pre.decapsulate_original(priv_bob, ekey_alice)
    assert sym_key_3 != sym_key


@pytest.mark.parametrize("N,threshold", [
    (10, 8),
    (3, 2),
    (5, 4),
    (1, 1),
    (3, 1),
    (100, 85),
    (100, 99),
    ])
def test_m_of_n(N, threshold):
    pre = umbral.PRE()
    priv_alice = pre.gen_priv()
    pub_alice = pre.priv2pub(priv_alice)
    priv_bob = pre.gen_priv()
    rk_ab = pre.rekey(priv_alice, priv_bob)

    sym_key, ekey_alice = pre.encapsulate(pub_alice)

    kfrags, vkeys = pre.split_rekey(priv_alice, priv_bob, threshold, N)

    for kfrag in kfrags:
        assert pre.check_kFrag_consistency(kfrag, vkeys)

    ekeys = [pre.reencrypt(rk, ekey_alice) for rk in kfrags[:threshold]]
    ekey_bob = pre.combine(ekeys)

    assert ekey_bob.ekey == ekey_alice.ekey ** rk_ab.key

    sym_key_2 = pre.decapsulate_reencrypted(priv_bob, ekey_bob, pub_alice, ekey_alice)
    assert sym_key_2 == sym_key

# @pytest.mark.parametrize("N,threshold", [
#     (10, 8),
#     (3, 2),
#     (5, 4),
#     (100, 85),
#     (100, 99),
#     (1, 1),
#     (3, 1)
#     ])
# def test_alice_sends_fake_kFrag_to_Ursula(N, threshold):
#     pre = umbral.PRE()
#     priv_alice = pre.gen_priv()
#     pub_alice = pre.priv2pub(priv_alice)
#     priv_bob = pre.gen_priv()
#     rk_ab = pre.rekey(priv_alice, priv_bob)

#     sym_key, ekey_alice = pre.encapsulate(pub_alice)

#     kfrags, vkeys = pre.split_rekey(priv_alice, priv_bob, threshold, N)

#     for kfrag in kfrags:
#         assert pre.check_kFrag_consistency(kfrag, vkeys)

#     # Alice tries to frame the first Ursula by sending her a random kFrag
#     fake_kfrag = kfrags[0]._replace(key=ec.random(pre.ecgroup, ec.ZR))
#     assert not pre.check_kFrag_consistency(fake_kfrag, vkeys)
