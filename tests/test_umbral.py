import pytest
from npre import umbral
from npre.umbral import RekeyFrag
import npre.elliptic_curve as ec


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


@pytest.mark.parametrize("N,threshold", [
    (10, 8),
    (3, 2),
    (5, 4),
    (100, 85),
    (100, 99),
    (1, 1),
    (3, 1)])
def test_m_of_n(N, threshold):
    pre = umbral.PRE()
    priv_alice = pre.gen_priv()
    pub_alice = pre.priv2pub(priv_alice)
    priv_bob = pre.gen_priv()
    rk_ab = pre.rekey(priv_alice, priv_bob)

    sym_key, ekey_alice = pre.encapsulate(pub_alice)

    kfrags = pre.split_rekey(priv_alice, priv_bob, threshold, N)
    ekeys = [pre.reencrypt(rk, ekey_alice) for rk in kfrags[:threshold]]
    ekey_bob = pre.combine(ekeys)

    assert ekey_bob.ekey == ekey_alice.ekey ** rk_ab.key

    sym_key_2 = pre.decapsulate(priv_bob, ekey_bob)
    assert sym_key_2 == sym_key

    return kfrags, pre


def test_kfrag_serialization():
    kfrags, pre = test_m_of_n(5, 5)
    some_particular_kfrag = kfrags[3]
    original_id = some_particular_kfrag.id
    serialized_id = ec.serialize(original_id)
    deserialized_id = ec.deserialize(pre.ecgroup, serialized_id)
    assert deserialized_id == original_id


def test_frag_as_bytes():
    kfrags, pre = test_m_of_n(5, 5)
    some_particular_kfrag = kfrags[3]
    kfrag_as_bytes = bytes(some_particular_kfrag)
    back_to_kfrag = RekeyFrag.from_bytes(kfrag_as_bytes)
    assert some_particular_kfrag == back_to_kfrag