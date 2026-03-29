"""
Test vectors for CHIP Silent Payments specification.

These tests generate and verify the intermediate cryptographic values
published in the CHIP's Test Cases section. Running these tests confirms
that the CHIP's test vectors are reproducible from the stated inputs
using the reference implementation.
"""
import hashlib

from chia_rs import PrivateKey

from shared import (
    GROUP_ORDER,
    aggregate_sender_pks,
    aggregate_sender_sks,
    calculate_synthetic_secret_key,
    compute_input_hash,
    compute_shared_secret_full,
    create_silent_payment_outputs,
    derive_onetime_pk_full,
    derive_onetime_sk_full,
    derive_output_tweak,
    encode_silent_payment_address,
    generate_label,
    generate_labeled_spend_pk,
    master_sk_to_scan_sk,
    master_sk_to_spend_sk,
    master_sk_to_wallet_sk,
    mnemonic_to_master_sk,
    puzzle_hash_for_pk,
    puzzle_hash_to_address,
    scalar_mult_g1,
    scan_for_silent_payment,
)

TEST_MNEMONIC_1 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
TEST_MNEMONIC_2 = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"


def test_vector_1_single_output():
    """Test Vector 1: Single output payment with all intermediate values.

    Sender and recipient both use TEST_MNEMONIC_1 (different derivation paths).
    Coin ID is SHA256("test-vector-1-coin").
    """
    # --- Key Derivation ---
    sender_master = mnemonic_to_master_sk(TEST_MNEMONIC_1)
    sender_wallet_sk = master_sk_to_wallet_sk(sender_master, 0)
    sender_syn_sk = calculate_synthetic_secret_key(sender_wallet_sk)
    sender_syn_pk = sender_syn_sk.get_g1()

    recip_master = mnemonic_to_master_sk(TEST_MNEMONIC_1)
    scan_sk = master_sk_to_scan_sk(recip_master)
    scan_pk = scan_sk.get_g1()
    spend_sk = master_sk_to_spend_sk(recip_master)
    spend_pk = spend_sk.get_g1()

    # Assert key derivation intermediate values
    assert bytes(sender_wallet_sk).hex() == "6c8d1a9f97413f8d8e8c158f5bc875b58b498de05c9109b4dc240280d32e2a31"
    assert bytes(sender_syn_sk).hex() == "5002eaf015c1c3a9694cc054e96273279732f4f963616ff89b6d4addcd678c7a"
    assert bytes(sender_syn_pk).hex() == "8d9a5ed9c9b1a58476b07262007c636d775f2a33f0533737f3b3b0eaf99a8c0c51b3f2d87dc03a657e07f1828ab760fa"
    assert bytes(scan_sk).hex() == "132567e4dec19a4f50d9e9a549f16283dfb5aa4ad1ffdb6a505fcfcc56a690f6"
    assert bytes(scan_pk).hex() == "a04f404bfbfdc9311736899fe32d2275bb007814510c3523529487ad7573607573ade20d31c75107b40331fff79ac896"
    assert bytes(spend_sk).hex() == "53d140b312a0e16316314274eb6398e15706d100fe8a754990540febd931b087"
    assert bytes(spend_pk).hex() == "8afc580192f44fab624f613369f792eff3220ea3ca822eb839ab2c9309e527dbf6f31e22e0831ba5088c952625a75c74"

    # Silent payment address
    sp_address = encode_silent_payment_address(bytes(scan_pk), bytes(spend_pk))
    assert sp_address.startswith("tspxch1")

    # --- Protocol Execution ---
    coin_id = hashlib.sha256(b"test-vector-1-coin").digest()
    assert coin_id.hex() == "5d759d2d97c03b1f6fe0657e91d25f6b7dd1311d6023271a1bcd35978a94a175"

    input_hash = compute_input_hash([coin_id], sender_syn_pk)
    assert hex(input_hash) == "0x38a1c8379cceb0fbebfdf3016707e54a1c7e9d21afb9489b9cc58f6055cc9411"

    # ECDH point S (for CHIP documentation)
    sender_scalar = int.from_bytes(bytes(sender_syn_sk), "big")
    adjusted_scalar = (input_hash * sender_scalar) % GROUP_ORDER
    ecdh_point = scalar_mult_g1(adjusted_scalar, scan_pk)
    assert bytes(ecdh_point).hex() == "aa15516b2b572ebedcd3c048c07189485f8374449923389534125e99763845700d6d84d8edaf73b6516874d9a798de09"

    shared_secret = compute_shared_secret_full(sender_syn_sk, scan_pk, input_hash)
    assert shared_secret.hex() == "d3ac1e8f651a73d2e20b43cb73fd6997de5504afbc04a2d4546a92d0020ba2c6"

    tweak = derive_output_tweak(shared_secret, 0)
    assert hex(tweak) == "0x5c560301c50fa309ad43d0f82cd1af143f6e3769659c80e8c14a072331582ab1"

    onetime_pk = derive_onetime_pk_full(spend_pk, tweak)
    assert bytes(onetime_pk).hex() == "b671487c1d275842f529f7a73a63a32a9a1a49e1dbabcac4058cc48626b6db31f48dc49e769a6f8076a9111ff14e964d"

    puzzle_hash = puzzle_hash_for_pk(onetime_pk)
    assert puzzle_hash.hex() == "23adba149dd9000d65e0f8e21b6975364cbe89a63caf56533df4b7664c21fbf5"

    address = puzzle_hash_to_address(puzzle_hash)
    assert address == "txch1ywkm59yamyqq6e0qlr3pk6t4xextazdx8jh4v5ea7jmkvnppl06swd5m0t"

    # --- Verification ---
    # Scanner using b_scan + A produces the same puzzle hash
    detected = scan_for_silent_payment(
        scan_sk, spend_pk, sender_syn_pk, [coin_id], [puzzle_hash]
    )
    assert len(detected) == 1
    assert detected[0]["puzzle_hash"] == puzzle_hash

    # Recipient derives spending key from b_spend + t_0
    onetime_sk = derive_onetime_sk_full(spend_sk, tweak)
    assert bytes(onetime_sk).hex() == "3c399c61ae130724903b3b650e936ff042b7646764289a33519e17100a89db37"
    assert onetime_sk.get_g1() == onetime_pk


def test_vector_2_multi_output():
    """Test Vector 2: Multi-output payment to two different recipients.

    Sender uses TEST_MNEMONIC_1. Recipient A uses TEST_MNEMONIC_1,
    Recipient B uses TEST_MNEMONIC_2. Coin ID is SHA256("test-vector-2-coin").
    """
    # --- Key Derivation ---
    sender_master = mnemonic_to_master_sk(TEST_MNEMONIC_1)
    sender_wallet_sk = master_sk_to_wallet_sk(sender_master, 0)
    sender_syn_sk = calculate_synthetic_secret_key(sender_wallet_sk)
    sender_syn_pk = sender_syn_sk.get_g1()

    # Recipient A
    recip_a_master = mnemonic_to_master_sk(TEST_MNEMONIC_1)
    scan_sk_a = master_sk_to_scan_sk(recip_a_master)
    scan_pk_a = scan_sk_a.get_g1()
    spend_pk_a = master_sk_to_spend_sk(recip_a_master).get_g1()

    # Recipient B
    recip_b_master = mnemonic_to_master_sk(TEST_MNEMONIC_2)
    scan_sk_b = master_sk_to_scan_sk(recip_b_master)
    scan_pk_b = scan_sk_b.get_g1()
    spend_sk_b = master_sk_to_spend_sk(recip_b_master)
    spend_pk_b = spend_sk_b.get_g1()

    # Assert recipient B key derivation
    assert bytes(scan_pk_b).hex() == "904b64222fcc0bcf254bcfadcd579cf0530b4fba7ed454f3e6d85799cc9f54913f048f1fb393e4acf1bbe56d09d73108"
    assert bytes(spend_pk_b).hex() == "99c454a391281b0c0c25ca8175d93ba9d6c4ce9dabe5a25e28b38c2e9ce66aabe50a73f64a477b212ce110dac1e79813"

    # --- Protocol Execution ---
    coin_id = hashlib.sha256(b"test-vector-2-coin").digest()
    assert coin_id.hex() == "b75c75c4787bade82b417272eff88ed90b3013a14b06c16be66b944856f378a2"

    input_hash = compute_input_hash([coin_id], sender_syn_pk)
    assert hex(input_hash) == "0x42b39c642d50849aa93f23c34085d80bb6a236cad4e0edd2841d526838c92b22"

    # Recipient A shared secret (same B_scan as vector 1)
    shared_secret_a = compute_shared_secret_full(sender_syn_sk, scan_pk_a, input_hash)
    assert shared_secret_a.hex() == "e9b20a7df882357c76abb4b5f87dcfc9a64cda6413c85f61efa1c4e81e1be50d"

    tweak_a = derive_output_tweak(shared_secret_a, 0)
    assert hex(tweak_a) == "0x13682ff0957fce11761842863c1658c4cfe9dad4b312fb5fcd71f66567d33d9b"

    onetime_pk_a = derive_onetime_pk_full(spend_pk_a, tweak_a)
    assert bytes(onetime_pk_a).hex() == "97b332699dfd7741b3f0c8bf1e1a0edef3b4ad7a092a8f38d74f17216cfb1d0f5abe7d853f8e3223407be827c9c3aaa8"

    puzzle_hash_a = puzzle_hash_for_pk(onetime_pk_a)
    assert puzzle_hash_a.hex() == "596275d286042c639d97e3765fe89d0e5554ac250e0fb4c594a9165017c0a9e5"

    address_a = puzzle_hash_to_address(puzzle_hash_a)
    assert address_a == "txch1t938t55xqskx88vhudm9l6yape24ftp9pc8mf3v54yt9q97q48jsqly0xr"

    # Recipient B shared secret (different B_scan)
    shared_secret_b = compute_shared_secret_full(sender_syn_sk, scan_pk_b, input_hash)
    assert shared_secret_b.hex() == "1450c748a04e4925bf34d0ef09e21fd1dab0eb0a3675efcb5b2da66d813c06e9"

    tweak_b = derive_output_tweak(shared_secret_b, 0)
    assert hex(tweak_b) == "0x21d2901f3189dc8def5c5a29e84933a5543ceabd131653dd2ea1951523045976"

    onetime_pk_b = derive_onetime_pk_full(spend_pk_b, tweak_b)
    assert bytes(onetime_pk_b).hex() == "a2557b2b6029fcc6783e8447588311a06b5d3dcad132a318d40bf0d6114595dd3d14fd58fe6f6c88dfa190aaa6bef873"

    puzzle_hash_b = puzzle_hash_for_pk(onetime_pk_b)
    assert puzzle_hash_b.hex() == "65249bcb907c9a6fac2e14499f6220cc24ba9359767d680c19405da06b69b263"

    address_b = puzzle_hash_to_address(puzzle_hash_b)
    assert address_b == "txch1v5jfhjus0jdxltpwz3ye7c3qesjt4y6ewe7ksrqegpw6q6mfkf3s0xpfcj"

    # Different recipients get different puzzle hashes and shared secrets
    assert puzzle_hash_a != puzzle_hash_b
    assert shared_secret_a != shared_secret_b

    # --- Verification via create_silent_payment_outputs ---
    outputs = create_silent_payment_outputs(
        sender_syn_sk, [coin_id],
        [(scan_pk_a, spend_pk_a), (scan_pk_b, spend_pk_b)]
    )
    assert outputs[0][1] == puzzle_hash_a
    assert outputs[1][1] == puzzle_hash_b

    # Scanner A detects their output
    detected_a = scan_for_silent_payment(
        scan_sk_a, spend_pk_a, sender_syn_pk, [coin_id],
        [puzzle_hash_a, puzzle_hash_b]
    )
    assert len(detected_a) == 1
    assert detected_a[0]["puzzle_hash"] == puzzle_hash_a

    # Scanner B detects their output
    detected_b = scan_for_silent_payment(
        scan_sk_b, spend_pk_b, sender_syn_pk, [coin_id],
        [puzzle_hash_a, puzzle_hash_b]
    )
    assert len(detected_b) == 1
    assert detected_b[0]["puzzle_hash"] == puzzle_hash_b


def test_vector_3_labeled_payment():
    """Test Vector 3: Labeled payment with label m=1.

    Sender and recipient both use TEST_MNEMONIC_1. Recipient uses label m=1.
    Coin ID is SHA256("test-vector-3-coin").
    """
    # --- Key Derivation ---
    sender_master = mnemonic_to_master_sk(TEST_MNEMONIC_1)
    sender_wallet_sk = master_sk_to_wallet_sk(sender_master, 0)
    sender_syn_sk = calculate_synthetic_secret_key(sender_wallet_sk)
    sender_syn_pk = sender_syn_sk.get_g1()

    recip_master = mnemonic_to_master_sk(TEST_MNEMONIC_1)
    scan_sk = master_sk_to_scan_sk(recip_master)
    scan_pk = scan_sk.get_g1()
    spend_sk = master_sk_to_spend_sk(recip_master)
    spend_pk = spend_sk.get_g1()

    # Generate label m=1
    label_scalar, label_pk = generate_label(scan_sk, 1)
    assert hex(label_scalar) == "0x48fa440acca87f501b9984b5d23327d0b7766a4baa913dfb3001d412c48ce465"
    assert bytes(label_pk).hex() == "a6dcff3646739745ef7f3ba8e51808dac13765fa9d5e73386d3fbd7841e0773e02a0f8d91baf57d337954322bd06d80c"

    labeled_spend_pk = generate_labeled_spend_pk(spend_pk, label_pk)
    assert bytes(labeled_spend_pk).hex() == "965250fb8503cff4c244f360ab84075bfe2da01091745d0e8ce36024ab12e96277d1f02fbbe01cee412dd2ce1b7414c2"

    # Labeled silent payment address
    labeled_sp_address = encode_silent_payment_address(bytes(scan_pk), bytes(labeled_spend_pk))
    assert labeled_sp_address.startswith("tspxch1")

    # --- Protocol Execution ---
    coin_id = hashlib.sha256(b"test-vector-3-coin").digest()
    assert coin_id.hex() == "4504f59ea184be18924f95244649287382ec6cdc13f333a8990f648c803a6dac"

    input_hash = compute_input_hash([coin_id], sender_syn_pk)
    assert hex(input_hash) == "0x58a1875602949aa6bfaf9cb4837957e7175ffb0b14422dbc8d371799f98e66f5"

    shared_secret = compute_shared_secret_full(sender_syn_sk, scan_pk, input_hash)
    assert shared_secret.hex() == "3d1eabb622c40142d4b2557fc222a22cd93d98550255cecb2b6a84985f49215d"

    tweak = derive_output_tweak(shared_secret, 0)
    assert hex(tweak) == "0x301e842ace534f7de854dcc5a48a656d7e9a6d8b8f93db9fb8277f4d1889bdf1"

    onetime_pk = derive_onetime_pk_full(labeled_spend_pk, tweak)
    assert bytes(onetime_pk).hex() == "97e7466509081a3ed6e50ba0231a6fa1b48d8c910ac6ec933e26cd5091569c615f299726c91a730dbf51a26cb249f17c"

    puzzle_hash = puzzle_hash_for_pk(onetime_pk)
    assert puzzle_hash.hex() == "ba271d218d487e8e5dc994a09a8580e1e8a0559a615bd5805cff11b5a343441c"

    address = puzzle_hash_to_address(puzzle_hash)
    assert address == "txch1hgn36gvdfplguhwfjjsf4pvqu852q4v6v9datqzulugmtg6rgswqpr9rsm"

    # --- Label Detection via Scanning ---
    labels_dict = {bytes(label_pk): 1}
    detected = scan_for_silent_payment(
        scan_sk, spend_pk, sender_syn_pk, [coin_id], [puzzle_hash],
        labels=labels_dict
    )
    assert len(detected) == 1
    assert detected[0]["label"] == 1
    assert detected[0]["k"] == 0
    assert detected[0]["puzzle_hash"] == puzzle_hash

    # --- Labeled Spending Key Derivation ---
    onetime_sk_base = derive_onetime_sk_full(spend_sk, detected[0]["tweak"])
    assert bytes(onetime_sk_base).hex() == "10021d8ab756b398cb4c4732864c264981e39a898e1ff4ea487b8f39f1bb6e77"

    labeled_onetime_scalar = (
        int.from_bytes(bytes(onetime_sk_base), "big") + label_scalar
    ) % GROUP_ORDER
    labeled_onetime_sk = PrivateKey.from_bytes(
        labeled_onetime_scalar.to_bytes(32, "big")
    )
    assert bytes(labeled_onetime_sk).hex() == "58fc619583ff32e8e6e5cbe8587f4e1a395a04d538b132e5787d634cb64852dc"

    # Key pair consistency: labeled one-time SK matches the one-time PK
    assert labeled_onetime_sk.get_g1() == onetime_pk


def test_vector_4_multi_input():
    """Test Vector 4: Multi-input payment with 2 sender coins.

    Sender uses TEST_MNEMONIC_1 at derivation indices 0 and 1.
    Recipient uses TEST_MNEMONIC_1 (scan/spend keys).
    Coin IDs: SHA256("test-vector-4-coin-0") and SHA256("test-vector-4-coin-1").
    """
    import hashlib as _hashlib

    # --- Key Derivation ---
    sender_master = mnemonic_to_master_sk(TEST_MNEMONIC_1)
    wallet_sk_0 = master_sk_to_wallet_sk(sender_master, 0)
    wallet_sk_1 = master_sk_to_wallet_sk(sender_master, 1)
    syn_sk_0 = calculate_synthetic_secret_key(wallet_sk_0)
    syn_sk_1 = calculate_synthetic_secret_key(wallet_sk_1)
    syn_pk_0 = syn_sk_0.get_g1()
    syn_pk_1 = syn_sk_1.get_g1()

    # Assert individual key intermediate values
    # syn_sk_0 and syn_pk_0 match test_vector_1
    assert bytes(syn_sk_0).hex() == "5002eaf015c1c3a9694cc054e96273279732f4f963616ff89b6d4addcd678c7a"
    assert bytes(syn_pk_0).hex() == "8d9a5ed9c9b1a58476b07262007c636d775f2a33f0533737f3b3b0eaf99a8c0c51b3f2d87dc03a657e07f1828ab760fa"

    # syn_sk_1 and syn_pk_1 are NEW values (derivation index 1)
    assert bytes(syn_sk_1).hex() == "05fded8808216b65d439fc41cb07c7270e37ed743e0745652afe055cfe91cf0f"
    assert bytes(syn_pk_1).hex() == "94c5c19f4343bc2655af729469285a392de9048851363b0b1329a4539a46ab4c6e8bfb39d32da25bffe4d9cdbe3e1061"

    # Aggregate keys
    agg_sk = aggregate_sender_sks([syn_sk_0, syn_sk_1])
    agg_pk = agg_sk.get_g1()

    # PK consistency: scalar sum's PK == point sum
    pk_sum = aggregate_sender_pks([syn_pk_0, syn_pk_1])
    assert agg_pk == pk_sum

    assert bytes(agg_sk).hex() == "5600d8781de32f0f3d86bc96b46a3a4ea56ae26da168b55dc66b503acbf95b89"
    assert bytes(agg_pk).hex() == "a223ab27f801044cd98c8314014b8073347b0e5aae43c69b78b5ca2a562ee9f799b8efad179b34da1b306ca4d62bad40"

    # Recipient keys (same as vector 1)
    recip_master = mnemonic_to_master_sk(TEST_MNEMONIC_1)
    scan_sk = master_sk_to_scan_sk(recip_master)
    scan_pk = scan_sk.get_g1()
    spend_sk = master_sk_to_spend_sk(recip_master)
    spend_pk = spend_sk.get_g1()

    # --- Protocol Execution ---
    coin_id_0 = _hashlib.sha256(b"test-vector-4-coin-0").digest()
    coin_id_1 = _hashlib.sha256(b"test-vector-4-coin-1").digest()

    # Assert coin IDs
    assert coin_id_0.hex() == "2b9857e0307ebfbe51829e3be8c992ae57f6a8debe06a5deab429ddae83a8c1a"
    assert coin_id_1.hex() == "209bb03a4cd165785e6149bc6dcb27e35829006f02ec927ab5a20521fd27d21a"

    # Lexicographic minimum coin ID (coin_id_1 < coin_id_0)
    min_coin_id = min(coin_id_0, coin_id_1)
    assert min_coin_id == coin_id_1
    assert min_coin_id.hex() == "209bb03a4cd165785e6149bc6dcb27e35829006f02ec927ab5a20521fd27d21a"

    input_hash = compute_input_hash([coin_id_0, coin_id_1], agg_pk)
    assert 0 < input_hash < GROUP_ORDER
    assert hex(input_hash) == "0x3f1071552b7f2f5e49b68166cb204f0a1b6a23b0c30a28bcba59a9c3f766e166"

    # ECDH point S (for CHIP documentation)
    sender_scalar = int.from_bytes(bytes(agg_sk), "big")
    adjusted_scalar = (input_hash * sender_scalar) % GROUP_ORDER
    ecdh_point = scalar_mult_g1(adjusted_scalar, scan_pk)
    assert bytes(ecdh_point).hex() == "b99921528f3e0b744040ad552d2209eae9092542f4968ab7a85a5c68098f09241a5d5112916f232fdd0edca5f0045080"

    shared_secret = compute_shared_secret_full(agg_sk, scan_pk, input_hash)
    assert shared_secret.hex() == "e729dea8c4732747d0e5e930607c52ddfce01ff7c72eaec9ee7c84131e078494"

    tweak = derive_output_tweak(shared_secret, 0)
    assert 0 < tweak < GROUP_ORDER
    assert hex(tweak) == "0x18fafd6001bef3fece078f469731b40a5f362994795f9ff6b9339aa235fee312"

    onetime_pk = derive_onetime_pk_full(spend_pk, tweak)
    assert bytes(onetime_pk).hex() == "b71f484e6d90a657b215ad7bff6f96a8d9bff07e0133d74917cc6c3ef6fa273a706aa56e1fd6da19ed5466f16450ccb1"

    puzzle_hash = puzzle_hash_for_pk(onetime_pk)
    assert puzzle_hash.hex() == "5d7fc7d7447c746cfb400e801a169fc7bfd1c13e03bc7866e6b743860a53ac6b"

    address = puzzle_hash_to_address(puzzle_hash)
    assert address == "txch1t4lu046y036xe76qp6qp595lc7larsf7qw78sehxkapcvzjn434s43wctu"

    # --- Scanner-Side Verification ---
    detected = scan_for_silent_payment(
        scan_sk, spend_pk, agg_pk, [coin_id_0, coin_id_1], [puzzle_hash]
    )
    assert len(detected) == 1
    assert detected[0]["puzzle_hash"] == puzzle_hash

    # --- Recipient Derives Spending Key ---
    onetime_sk = derive_onetime_sk_full(spend_sk, tweak)
    assert bytes(onetime_sk).hex() == "6ccc3e13145fd561e438d1bb82954cebb63cfa9577ea15404987aa8e0f309399"
    assert onetime_sk.get_g1() == onetime_pk

    # --- create_silent_payment_outputs consistency ---
    outputs = create_silent_payment_outputs(
        [syn_sk_0, syn_sk_1],
        [coin_id_0, coin_id_1],
        [(scan_pk, spend_pk)],
    )
    assert outputs[0][1] == puzzle_hash
