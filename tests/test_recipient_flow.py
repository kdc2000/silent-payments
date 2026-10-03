"""Recipient flow: scan with the scan key and the spend PUBLIC key, spend from the tweak.

End-to-end, OFFLINE checks of the CHIP-0057 recipient behaviour, run against the
SDK's in-process ``Simulator`` (real CLVM execution and real AGG_SIG_ME signature
validation — no chain, no ``coinset`` process, no Sage):

* scanning needs the scan secret key and the spend PUBLIC key only; the spend
  secret key enters when the coin is spent, through the detection's tweak;
* scanner records and script output carry k, label and the tweak, never a
  one-time SECRET key;
* the change label m = 0 is detected with no label registered (label 0);
* ``--legacy-keys`` (the unhardened derivation of addresses generated before the
  CHIP's hardened-derivation revision) on scan_coin.py / scanner.py /
  spend_coin.py, and the watch-only ``--scan-key`` / ``--spend-key`` scanner mode;
* send_payment.py rejects an invalid or wrong-network address before any lookup.

The script ``main()`` functions are driven with ``coinset.subprocess.run`` MOCKED
by a dispatcher that answers from the simulator's state, so the scripts' own code
paths (argument parsing, detection, tweak -> one-time key, spend build, signing,
wire bridge, push) run for real while nothing leaves the process.
"""

import json
import sys
from unittest import mock

import pytest

import chia_rs
import chia_wallet_sdk as sdk

import coinset
import scan_coin
import scanner
import sdk_adapter
import send_payment
import shared
import spend_coin

# Public BIP-39 test mnemonics (never real wallets).
RECIPIENT = (
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon about"
)
SENDER = "legal winner thank year wave sausage worth useful legal winner thank yellow"


# --------------------------------------------------------------------------
# simulator helpers
# --------------------------------------------------------------------------

def _fund(sim, index: int, amount: int) -> dict:
    """A simulator coin at the sender's standard wallet index -> adapter input dict."""
    wallet_pk, wallet_sk, synthetic_sk = sdk_adapter.wallet_keys(SENDER, index)
    puzzle_hash = sdk_adapter.wallet_puzzle_hash(SENDER, index)
    coin = sim.new_coin(puzzle_hash, amount)
    return {
        "parent_coin_info": coin.parent_coin_info,
        "puzzle_hash": puzzle_hash,
        "amount": amount,
        "wallet_pk": wallet_pk,
        "wallet_sk": wallet_sk,
        "synthetic_sk": synthetic_sk,
    }


def _send(sim, address: str, amount: int, inputs: list, fee: int = 0) -> int:
    """Build + sign a silent payment through the adapter and farm it.

    Returns the height of the block that includes it. ``sim.new_transaction``
    validates the adapter's manual AGG_SIG_ME signatures for real.
    """
    change_ph = sdk_adapter.default_change_puzzle_hash(SENDER)
    coin_spends = sdk_adapter.build_silent_payment_send(address, inputs, change_ph, amount, fee)
    bundle = sdk_adapter.build_signed_spend_bundle(
        coin_spends, [inp["synthetic_sk"] for inp in inputs]
    )
    height = sim.height()
    sim.new_transaction(bundle)
    return height


def _block_tweak_data(sim, height: int):
    return sdk_adapter.tweak_data_from_block_spends(
        sim.block_spends(height), sim.block_outputs(height)
    )


def _spend_record(sim, record: dict, spend_sk, dest_ph: bytes):
    """Spend a detected coin from its plain-dict record + the spend SECRET key."""
    onetime_sk = sdk_adapter.derive_onetime_sk(spend_sk, record["tweak"])
    coin = (
        bytes.fromhex(record["parent_coin_id"]),
        bytes.fromhex(record["puzzle_hash"]),
        record["amount"],
    )
    coin_spends = sdk_adapter.build_spend_to_address(
        onetime_sk, coin, dest_ph, record["amount"], fee=0
    )
    bundle = sdk_adapter.build_signed_spend_bundle(coin_spends, [onetime_sk.derive_synthetic()])
    sim.new_transaction(bundle)


def _is_spent(sim, coin_id_hex: str) -> bool:
    state = sim.coin_state(bytes.fromhex(coin_id_hex))
    assert state is not None, "coin is unknown to the simulator"
    return state.spent_height is not None


# --------------------------------------------------------------------------
# scan without the spend secret key, then spend with it
# --------------------------------------------------------------------------

def test_scan_without_spend_secret_key_then_spend_with_it():
    """A watch-only scanner (scan secret key + spend PUBLIC key, both as hex)
    detects the payment and produces a record with k / label / tweak and no
    secret key. The holder of the spend secret key then spends the coin from that
    record alone; a wrong spend key cannot."""
    sim = sdk.Simulator()
    keys = sdk_adapter.keys_from_mnemonic(RECIPIENT)  # hardened (CHIP-0057)
    height = _send(sim, sdk_adapter.encode_silent_payment_address(keys), 2_500, [_fund(sim, 0, 5_000)], fee=10)

    # --- watch-only side: no spend secret key in scope ---------------------
    scan_sk, spend_pk = sdk_adapter.watch_only_keys(
        keys.scan_sk().to_bytes().hex(), keys.spend_pk().to_bytes().hex()
    )
    detections = sdk_adapter.scan_from_tweaks(
        scan_sk, spend_pk, _block_tweak_data(sim, height), sdk_adapter.label_registry(scan_sk, [])
    )
    records = sdk_adapter.detections_to_records(detections, block_height=height)
    assert len(records) == 1
    record = records[0]
    assert set(record) == {
        "coin_id", "parent_coin_id", "puzzle_hash", "amount", "block_height",
        "k", "label", "tweak",
    }
    assert (record["amount"], record["k"], record["label"]) == (2_500, 0, None)
    assert not _is_spent(sim, record["coin_id"])

    # The record holds no secret: neither the one-time key nor the spend key.
    onetime_sk = sdk_adapter.derive_onetime_sk(keys.spend_sk(), record["tweak"])
    dumped = json.dumps(record)
    assert onetime_sk.to_bytes().hex() not in dumped
    assert keys.spend_sk().to_bytes().hex() not in dumped

    # --- a wrong spend secret key does not open the coin --------------------
    dest_ph = sdk_adapter.wallet_puzzle_hash(RECIPIENT, 0)
    with pytest.raises(ValueError):
        _spend_record(sim, record, keys.scan_sk(), dest_ph)
    assert not _is_spent(sim, record["coin_id"])

    # --- the spend secret key, applied to the record's tweak, spends it -----
    _spend_record(sim, record, keys.spend_sk(), dest_ph)
    assert _is_spent(sim, record["coin_id"])
    assert [c.amount for c in sim.unspent_coins(dest_ph, False)] == [2_500]


@pytest.mark.parametrize("label", [None, 0, 3], ids=["unlabeled", "change-m0", "label-m3"])
def test_labels_detect_and_spend(label):
    """Unlabeled, change (m = 0) and labeled (m = 3) outputs: detected with the
    right label, and spendable from the tweak (which already includes the label
    scalar). The change label is found with NO label registered."""
    sim = sdk.Simulator()
    keys = sdk_adapter.keys_from_mnemonic(RECIPIENT)
    if label is None:
        address = sdk_adapter.encode_silent_payment_address(keys)
    elif label == 0:
        address = sdk_adapter.change_address(keys)
    else:
        address = sdk_adapter.labeled_address(keys, label)
    height = _send(sim, address, 700, [_fund(sim, 1, 1_000)])

    registered = [label] if label else []  # nothing registered for None / change
    registry = sdk_adapter.label_registry(keys.scan_sk(), registered)
    assert registry.is_empty() == (not registered)
    detections = sdk_adapter.scan_from_tweaks(
        keys.scan_sk(), keys.spend_pk(), _block_tweak_data(sim, height), registry
    )
    records = sdk_adapter.detections_to_records(detections, block_height=height)
    assert [(r["amount"], r["k"], r["label"]) for r in records] == [(700, 0, label)]

    dest_ph = sdk_adapter.wallet_puzzle_hash(RECIPIENT, 0)
    _spend_record(sim, records[0], keys.spend_sk(), dest_ph)
    assert _is_spent(sim, records[0]["coin_id"])


def test_labeled_output_is_missed_when_its_label_is_not_registered():
    """A label m >= 1 is only found when registered (unlike the change label)."""
    sim = sdk.Simulator()
    keys = sdk_adapter.keys_from_mnemonic(RECIPIENT)
    height = _send(sim, sdk_adapter.labeled_address(keys, 3), 700, [_fund(sim, 1, 1_000)])
    tweak_data = _block_tweak_data(sim, height)

    def scan(indices):
        return sdk_adapter.scan_from_tweaks(
            keys.scan_sk(), keys.spend_pk(), tweak_data,
            sdk_adapter.label_registry(keys.scan_sk(), indices),
        )

    assert scan([]) == []
    assert scan([1, 2]) == []
    assert [d.label for d in scan([1, 2, 3])] == [3]


def test_multi_input_send_is_bound_detected_and_spent():
    """Three coins at three wallet indices: the adapter binds them with the
    ASSERT_CONCURRENT_SPEND cycle, the simulator accepts the signed bundle, the
    scanner regroups the inputs and detects the output, and it is spendable."""
    sim = sdk.Simulator()
    keys = sdk_adapter.keys_from_mnemonic(RECIPIENT)
    inputs = [_fund(sim, i, 1_000) for i in range(3)]
    height = _send(sim, sdk_adapter.encode_silent_payment_address(keys), 2_500, inputs, fee=5)

    spends = sim.block_spends(height)
    assert len(spends) == 3
    tweak_data = _block_tweak_data(sim, height)
    # 3 single-input groups + 1 multi-input group (the 3-cycle).
    assert len(tweak_data.tweak_points) == 4

    detections = sdk_adapter.scan_from_tweaks(
        keys.scan_sk(), keys.spend_pk(), tweak_data,
        sdk_adapter.label_registry(keys.scan_sk(), []),
    )
    records = sdk_adapter.detections_to_records(detections, block_height=height)
    assert [(r["amount"], r["k"], r["label"]) for r in records] == [(2_500, 0, None)]
    _spend_record(sim, records[0], keys.spend_sk(), sdk_adapter.wallet_puzzle_hash(RECIPIENT, 0))
    assert _is_spent(sim, records[0]["coin_id"])


def test_selected_mixed_index_coins_are_detected_and_spent():
    """send_payment.select_coins picks the largest coins whatever their wallet
    derivation index. A payment funded by such a mixed-index selection is bound
    by the ASSERT_CONCURRENT_SPEND cycle, found by the scanner as ONE multi-input
    group, and spendable — no same-index restriction is needed."""
    sim = sdk.Simulator()
    keys = sdk_adapter.keys_from_mnemonic(RECIPIENT)

    # Four coins at four different wallet indices; no single coin covers 1,500.
    amounts = {0: 300, 3: 900, 5: 700, 7: 200}
    funded = {index: _fund(sim, index, amount) for index, amount in amounts.items()}
    coin_infos = [
        {
            "coin_id": shared.compute_coin_id(
                inp["parent_coin_info"], inp["puzzle_hash"], inp["amount"]
            ),
            "amount": inp["amount"],
            "derivation_index": index,
        }
        for index, inp in funded.items()
    ]

    selected = send_payment.select_coins(coin_infos, 1_500 + 10)
    assert [c["derivation_index"] for c in selected] == [3, 5]  # 900 + 700, two indices
    inputs = [funded[c["derivation_index"]] for c in selected]

    height = _send(sim, sdk_adapter.encode_silent_payment_address(keys), 1_500, inputs, fee=10)
    assert len(sim.block_spends(height)) == 2
    tweak_data = _block_tweak_data(sim, height)
    # 2 single-input groups + 1 multi-input group (the 2-cycle).
    assert len(tweak_data.tweak_points) == 3

    detections = sdk_adapter.scan_from_tweaks(
        keys.scan_sk(), keys.spend_pk(), tweak_data,
        sdk_adapter.label_registry(keys.scan_sk(), []),
    )
    records = sdk_adapter.detections_to_records(detections, block_height=height)
    assert [(r["amount"], r["k"], r["label"]) for r in records] == [(1_500, 0, None)]
    _spend_record(sim, records[0], keys.spend_sk(), sdk_adapter.wallet_puzzle_hash(RECIPIENT, 0))
    assert _is_spent(sim, records[0]["coin_id"])


def test_single_input_send_emits_no_binding_condition():
    """One spent coin: Relation.AssertConcurrent is passed but nothing is emitted
    (CHIP-0057: a payment funded by a single coin needs no such condition)."""
    sim = sdk.Simulator()
    keys = sdk_adapter.keys_from_mnemonic(RECIPIENT)
    inp = _fund(sim, 0, 5_000)
    coin_spends = sdk_adapter.build_silent_payment_send(
        sdk_adapter.encode_silent_payment_address(keys), [inp],
        sdk_adapter.default_change_puzzle_hash(SENDER), 2_500, 10,
    )
    assert len(coin_spends) == 1
    clvm = sdk.Clvm()
    output = clvm.deserialize(bytes(coin_spends[0].puzzle_reveal)).run(
        clvm.deserialize(bytes(coin_spends[0].solution)), 11_000_000_000, False
    )
    conditions = output.value.to_list()
    assert conditions is not None
    assert [c for c in conditions if c.parse_assert_concurrent_spend() is not None] == []
    assert len([c for c in conditions if c.parse_create_coin() is not None]) == 2


def test_hardened_and_legacy_keys_do_not_detect_each_others_coins():
    """One mnemonic, two addresses: a payment to the legacy (unhardened) address is
    found only with the legacy keys, a payment to the hardened address only with
    the hardened keys."""
    hardened = sdk_adapter.keys_from_mnemonic(RECIPIENT)
    legacy = sdk_adapter.legacy_unhardened_keys_from_mnemonic(RECIPIENT)
    assert sdk_adapter.encode_silent_payment_address(hardened) != (
        sdk_adapter.encode_silent_payment_address(legacy)
    )

    for paid, other in ((hardened, legacy), (legacy, hardened)):
        sim = sdk.Simulator()
        height = _send(sim, sdk_adapter.encode_silent_payment_address(paid), 900, [_fund(sim, 0, 1_000)])
        tweak_data = _block_tweak_data(sim, height)

        def scan(keys):
            return sdk_adapter.scan_from_tweaks(
                keys.scan_sk(), keys.spend_pk(), tweak_data,
                sdk_adapter.label_registry(keys.scan_sk(), []),
            )

        assert len(scan(paid)) == 1
        assert scan(other) == []


# --------------------------------------------------------------------------
# sender-side address checks
# --------------------------------------------------------------------------

def test_send_rejects_wrong_network_and_invalid_addresses():
    """The adapter refuses a mainnet address on testnet (CHIP-0057: a sender SHOULD
    reject an address for another network) and any invalid address."""
    sim = sdk.Simulator()
    keys = sdk_adapter.keys_from_mnemonic(RECIPIENT)
    change_ph = sdk_adapter.default_change_puzzle_hash(SENDER)
    inp = _fund(sim, 0, 1_000)

    mainnet = sdk_adapter.encode_silent_payment_address(keys, sdk.SilentPaymentNetwork.Mainnet)
    assert mainnet.startswith("spxch1")
    assert sdk_adapter.silent_payment_address_is_testnet(mainnet) is False
    with pytest.raises(ValueError, match="wrong network"):
        sdk_adapter.build_silent_payment_send(mainnet, [inp], change_ph, 500)
    # ... and is accepted when the caller says it transacts on mainnet.
    assert len(sdk_adapter.build_silent_payment_send(mainnet, [inp], change_ph, 500, testnet=False)) == 1

    testnet = sdk_adapter.encode_silent_payment_address(keys)
    for bad in (testnet[:-1] + ("q" if testnet[-1] != "q" else "p"), "txch1" + testnet[7:], "tspxch1qqqq"):
        with pytest.raises(ValueError):
            sdk_adapter.build_silent_payment_send(bad, [inp], change_ph, 500)


@pytest.mark.parametrize("kind", ["mainnet", "garbage"])
def test_send_payment_script_rejects_bad_address_before_any_lookup(kind, capsys):
    """send_payment.py exits on a mainnet or invalid address without touching
    coinset or Sage."""
    keys = sdk_adapter.keys_from_mnemonic(RECIPIENT)
    address = (
        sdk_adapter.encode_silent_payment_address(keys, sdk.SilentPaymentNetwork.Mainnet)
        if kind == "mainnet"
        else "tspxch1notanaddress"
    )
    with mock.patch("coinset.subprocess.run") as run, mock.patch.object(
        sys, "argv", ["send_payment.py", address, *SENDER.split()]
    ):
        with pytest.raises(SystemExit) as exc:
            send_payment.main()
    assert exc.value.code == 1
    assert run.call_count == 0
    err = capsys.readouterr().err
    assert ("tspxch1" in err) if kind == "mainnet" else ("Invalid silent payment address" in err)


# --------------------------------------------------------------------------
# the scripts' main(), with coinset answered from the simulator
# --------------------------------------------------------------------------

def _hex(b) -> str:
    return "0x" + bytes(b).hex()


def _coin_json(coin) -> dict:
    return {
        "parent_coin_info": _hex(coin.parent_coin_info),
        "puzzle_hash": _hex(coin.puzzle_hash),
        "amount": coin.amount,
    }


def _coinset_backed_by(sim, pushed: list):
    """A ``subprocess.run`` stand-in answering coinset CLI calls from ``sim``.

    ``coinset.call`` builds ``["coinset", *BASE_ARGS, "-r", command, *args]``.
    A pushed bundle is appended to ``pushed`` (as the wire dict) and farmed into
    the simulator, so a rejected bundle fails exactly as a node would reject it.
    """

    def reply(body: dict):
        return mock.Mock(returncode=0, stdout=json.dumps(body), stderr="")

    def dispatch(cmd, **_kwargs):
        assert cmd[0] == "coinset"
        at = cmd.index("-r")
        command, args = cmd[at + 1], cmd[at + 2:]
        if command == "get_coin_record_by_name":
            state = sim.coin_state(bytes.fromhex(args[0][2:]))
            if state is None:
                return reply({"success": False, "error": "not found"})
            return reply({"success": True, "coin_record": {
                "coin": _coin_json(state.coin),
                "spent": state.spent_height is not None,
                "coinbase": False,
            }})
        if command == "get_puzzle_and_solution":
            coin_spend = sim.coin_spend(bytes.fromhex(args[0][2:]))
            if coin_spend is None:
                return reply({"success": False, "error": "not spent"})
            return reply({"success": True, "coin_solution": {
                "puzzle_reveal": _hex(coin_spend.puzzle_reveal),
                "solution": _hex(coin_spend.solution),
            }})
        if command == "get_blockchain_state":
            return reply({"success": True, "blockchain_state": {"peak": {"height": sim.height() - 1}}})
        if command == "get_block_records":
            start, end = int(args[0]), int(args[1])
            return reply({"block_records": [
                {"height": h, "timestamp": 1_700_000_000 + h}
                for h in range(start, min(end, sim.height()))
            ]})
        if command == "get_additions_and_removals":
            height = int(args[0])
            return reply({
                "additions": [{"coin": _coin_json(c), "coinbase": False} for c in sim.block_outputs(height)],
                "removals": [{"coin": _coin_json(cs.coin), "coinbase": False} for cs in sim.block_spends(height)],
            })
        if command == "push_tx":
            wire = json.loads(args[0])
            pushed.append(wire)
            bundle = sdk.SpendBundle.from_bytes(bytes(chia_rs.SpendBundle.from_json_dict(wire)))
            try:
                sim.new_transaction(bundle)
            except ValueError as exc:
                return reply({"success": False, "error": str(exc)})
            return reply({"success": True, "status": "SUCCESS"})
        raise AssertionError(f"unexpected coinset command {command!r}")

    return dispatch


def _run_main(module, argv, sim, pushed=None):
    """Run a script's main() with argv and coinset answered from the simulator."""
    with mock.patch("coinset.subprocess.run", side_effect=_coinset_backed_by(sim, [] if pushed is None else pushed)), \
            mock.patch.object(coinset, "BASE_ARGS", ["-t"]), \
            mock.patch.object(sys, "argv", [module.__name__ + ".py", *argv]):
        module.main()


def _paid_coin(sim, keys, amount=2_500, label_address=None):
    """Pay ``keys`` in the simulator; return (height, record of the paid coin)."""
    address = label_address or sdk_adapter.encode_silent_payment_address(keys)
    height = _send(sim, address, amount, [_fund(sim, 0, 5_000)])
    detections = sdk_adapter.scan_from_tweaks(
        keys.scan_sk(), keys.spend_pk(), _block_tweak_data(sim, height),
        sdk_adapter.label_registry(keys.scan_sk(), []),
    )
    (record,) = sdk_adapter.detections_to_records(detections, block_height=height)
    return height, record


@pytest.mark.parametrize("legacy", [False, True], ids=["hardened", "legacy-keys"])
def test_scan_coin_script_prints_tweak_not_secret(legacy, capsys):
    """scan_coin.py reports MATCH with k, label and the tweak, and never prints a
    secret key. With --legacy-keys it derives the old unhardened keys and warns."""
    sim = sdk.Simulator()
    keys = (
        sdk_adapter.legacy_unhardened_keys_from_mnemonic(RECIPIENT)
        if legacy
        else sdk_adapter.keys_from_mnemonic(RECIPIENT)
    )
    _height, record = _paid_coin(sim, keys)
    onetime_sk_hex = sdk_adapter.derive_onetime_sk(keys.spend_sk(), record["tweak"]).to_bytes().hex()

    argv = [record["coin_id"], *RECIPIENT.split()] + (["--legacy-keys"] if legacy else [])
    _run_main(scan_coin, argv, sim)
    out, err = capsys.readouterr()

    assert "MATCH! This coin belongs to you." in out
    assert record["puzzle_hash"] in out
    assert f"Tweak:                {record['tweak']}" in out
    assert "Output index k:       0" in out
    assert "Label:                none" in out
    for text in (out, err):
        assert "secret key" not in text.lower()
        assert onetime_sk_hex not in text
        assert keys.spend_sk().to_bytes().hex() not in text
        assert keys.scan_sk().to_bytes().hex() not in text
    assert (sdk_adapter.LEGACY_KEYS_WARNING in err) == legacy

    # The printed tweak is the spend handoff.
    _spend_record(sim, record, keys.spend_sk(), sdk_adapter.wallet_puzzle_hash(RECIPIENT, 0))
    assert _is_spent(sim, record["coin_id"])


def test_scan_coin_script_needs_legacy_flag_for_a_legacy_coin(capsys):
    """A coin paid to the legacy address is NOT matched by the default (hardened)
    keys of the same mnemonic — --legacy-keys is required."""
    sim = sdk.Simulator()
    _height, record = _paid_coin(sim, sdk_adapter.legacy_unhardened_keys_from_mnemonic(RECIPIENT))

    _run_main(scan_coin, [record["coin_id"], *RECIPIENT.split()], sim)
    out, err = capsys.readouterr()
    assert "NO MATCH" in out
    assert sdk_adapter.LEGACY_KEYS_WARNING not in err


def test_scan_coin_script_reports_change_label(capsys):
    """A change output (label m = 0) is matched and shown as the change label."""
    sim = sdk.Simulator()
    keys = sdk_adapter.keys_from_mnemonic(RECIPIENT)
    _height, record = _paid_coin(sim, keys, label_address=sdk_adapter.change_address(keys))
    assert record["label"] == 0

    _run_main(scan_coin, [record["coin_id"], *RECIPIENT.split()], sim)
    out, _err = capsys.readouterr()
    assert "MATCH!" in out
    assert "Label:                0 (change)" in out


@pytest.mark.parametrize("legacy", [False, True], ids=["hardened", "legacy-keys"])
def test_spend_coin_script_spends_the_detected_coin(legacy, capsys):
    """spend_coin.py detects with scan key + spend public key, derives the one-time
    key from the tweak and the spend secret key, and pushes a bundle the simulator
    accepts: the coin is spent to the recipient's standard wallet (m/12381/8444/2/0)."""
    sim = sdk.Simulator()
    keys = (
        sdk_adapter.legacy_unhardened_keys_from_mnemonic(RECIPIENT)
        if legacy
        else sdk_adapter.keys_from_mnemonic(RECIPIENT)
    )
    _height, record = _paid_coin(sim, keys)
    assert not _is_spent(sim, record["coin_id"])

    pushed = []
    argv = [record["coin_id"], *RECIPIENT.split()] + (["--legacy-keys"] if legacy else [])
    _run_main(spend_coin, argv, sim, pushed)
    out, err = capsys.readouterr()

    assert "SUCCESS! Transaction submitted via coinset (push_tx)." in out
    assert (sdk_adapter.LEGACY_KEYS_WARNING in err) == legacy
    assert len(pushed) == 1 and len(pushed[0]["coin_spends"]) == 1
    assert _is_spent(sim, record["coin_id"])
    dest_ph = sdk_adapter.wallet_puzzle_hash(RECIPIENT, 0)
    assert [c.amount for c in sim.unspent_coins(dest_ph, False)] == [record["amount"]]

    onetime_sk_hex = sdk_adapter.derive_onetime_sk(keys.spend_sk(), record["tweak"]).to_bytes().hex()
    assert onetime_sk_hex not in out and onetime_sk_hex not in err


def test_spend_coin_script_without_legacy_flag_does_not_match_a_legacy_coin(capsys):
    """Default (hardened) keys on a legacy-paid coin: NO MATCH, exit 1, nothing pushed."""
    sim = sdk.Simulator()
    _height, record = _paid_coin(sim, sdk_adapter.legacy_unhardened_keys_from_mnemonic(RECIPIENT))

    pushed = []
    with pytest.raises(SystemExit) as exc:
        _run_main(spend_coin, [record["coin_id"], *RECIPIENT.split()], sim, pushed)
    assert exc.value.code == 1
    assert "NO MATCH" in capsys.readouterr().out
    assert pushed == []
    assert not _is_spent(sim, record["coin_id"])


def test_scanner_script_watch_only(capsys):
    """scanner.py --scan-key/--spend-key scans a block range with no mnemonic and
    no spend secret key, and prints k, label and the tweak for each detection."""
    sim = sdk.Simulator()
    keys = sdk_adapter.keys_from_mnemonic(RECIPIENT)
    height, record = _paid_coin(sim, keys)

    argv = [
        "-s", str(height), "-e", str(height),
        "--scan-key", keys.scan_sk().to_bytes().hex(),
        "--spend-key", "0x" + keys.spend_pk().to_bytes().hex(),
        sdk_adapter.encode_silent_payment_address(keys),
    ]
    with mock.patch.object(scanner, "load_mnemonic", side_effect=AssertionError("no mnemonic in watch-only mode")):
        _run_main(scanner, argv, sim)
    out, err = capsys.readouterr()

    assert f"Coin ID:      {record['coin_id']}" in out
    assert f"Amount:       {record['amount']} mojos" in out
    assert f"Block Height: {height}" in out
    assert "Output k:     0" in out
    assert "Label:        none" in out
    assert f"Tweak:        {record['tweak']}" in out
    assert f"Address:      {shared.puzzle_hash_to_address(bytes.fromhex(record['puzzle_hash']))}" in out
    assert "Found 1 silent payment(s):" in err
    assert "does not match" not in err
    onetime_sk_hex = sdk_adapter.derive_onetime_sk(keys.spend_sk(), record["tweak"]).to_bytes().hex()
    for text in (out, err):
        assert onetime_sk_hex not in text
        assert keys.spend_sk().to_bytes().hex() not in text


@pytest.mark.parametrize("legacy", [False, True], ids=["hardened", "legacy-keys"])
def test_scanner_script_mnemonic_modes(legacy, capsys):
    """scanner.py with a mnemonic: hardened keys by default, the old unhardened
    keys (with the warning) under --legacy-keys."""
    sim = sdk.Simulator()
    paid_keys = (
        sdk_adapter.legacy_unhardened_keys_from_mnemonic(RECIPIENT)
        if legacy
        else sdk_adapter.keys_from_mnemonic(RECIPIENT)
    )
    height, record = _paid_coin(sim, paid_keys)

    argv = ["-s", str(height), "-e", str(height)] + (["--legacy-keys"] if legacy else [])
    with mock.patch.object(scanner, "load_mnemonic", return_value=RECIPIENT):
        _run_main(scanner, argv, sim)
    out, err = capsys.readouterr()
    assert f"Coin ID:      {record['coin_id']}" in out
    assert f"Tweak:        {record['tweak']}" in out
    assert (sdk_adapter.LEGACY_KEYS_WARNING in err) == legacy

    # The other derivation finds nothing in the same block.
    other_argv = ["-s", str(height), "-e", str(height)] + ([] if legacy else ["--legacy-keys"])
    with mock.patch.object(scanner, "load_mnemonic", return_value=RECIPIENT):
        _run_main(scanner, other_argv, sim)
    out, err = capsys.readouterr()
    assert "Found 0 silent payment(s):" in err
    assert "Coin ID" not in out


@pytest.mark.parametrize(
    "argv",
    [
        ["-s", "1", "--scan-key", "11" * 32],                                   # no spend key
        ["-s", "1", "--spend-key", "aa" * 48],                                  # no scan key
        ["-s", "1", "--scan-key", "11" * 32, "--spend-key", "c0" + "00" * 47],  # identity spend key
        ["-s", "1", "--scan-key", "00" * 32, "--spend-key", "PK"],              # zero scan key
        ["-s", "1", "--scan-key", "11" * 32, "--spend-key", "PK", "--legacy-keys"],
        ["-s", "1", "--scan-key", "11" * 32, "--spend-key", "PK", "-f", "keyfile.txt"],
    ],
    ids=["scan-only", "spend-only", "identity-spend-pk", "zero-scan-sk", "with-legacy", "with-file"],
)
def test_scanner_script_rejects_bad_watch_only_arguments(argv, capsys):
    """Incomplete, invalid or contradictory watch-only arguments exit with a usage
    error before any coinset call."""
    spend_pk_hex = sdk_adapter.keys_from_mnemonic(RECIPIENT).spend_pk().to_bytes().hex()
    argv = [spend_pk_hex if a == "PK" else a for a in argv]
    with mock.patch("coinset.subprocess.run") as run, mock.patch.object(
        sys, "argv", ["scanner.py", *argv]
    ), mock.patch.object(scanner, "load_mnemonic", side_effect=AssertionError("must not prompt")):
        with pytest.raises(SystemExit) as exc:
            scanner.main()
    assert exc.value.code == 2
    assert run.call_count == 0
    capsys.readouterr()


def test_legacy_flag_exists_only_on_the_three_recipient_scripts():
    """--legacy-keys is offered by scan_coin.py and spend_coin.py (module parsers)
    and scanner.py; generate_address.py and send_payment.py do not have it."""
    import generate_address

    def options(parser):
        return {opt for action in parser._actions for opt in action.option_strings}

    assert "--legacy-keys" in options(scan_coin.parser)
    assert "--legacy-keys" in options(spend_coin.parser)
    assert "--legacy-keys" not in options(generate_address.parser)
    assert "--legacy-keys" not in options(send_payment.parser)
    # scanner.py builds its parser inside main(); its source carries the flag.
    import inspect

    assert '"--legacy-keys"' in inspect.getsource(scanner.main)
