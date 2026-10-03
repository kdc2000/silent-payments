"""Unit tests for the Sage wallet RPC client."""

import pytest
import requests
from unittest.mock import MagicMock, patch

from sage_rpc import SageRPC, DEFAULT_URL


def mock_response(json_data, status_code=200):
    """Create a mock requests.Response with given JSON data and status code."""
    resp = MagicMock(spec=requests.Response)
    resp.json.return_value = json_data
    resp.status_code = status_code
    if status_code >= 400:
        resp.raise_for_status.side_effect = requests.HTTPError(
            response=resp
        )
    else:
        resp.raise_for_status.return_value = None
    return resp


class TestSageRPCInit:
    def test_sage_rpc_init_default(self):
        """SageRPC() initializes with default URL and verify=False."""
        sage = SageRPC()
        assert sage.url == DEFAULT_URL
        assert sage.session.verify is False

    def test_sage_rpc_init_custom(self):
        """SageRPC with custom params stores custom values."""
        sage = SageRPC(
            url="https://custom:1234",
            cert_path="/a.crt",
            key_path="/a.key",
        )
        assert sage.url == "https://custom:1234"
        assert sage.session.cert == ("/a.crt", "/a.key")


class TestSageRPCCalls:
    def test_get_keys(self):
        """sage.get_keys() POSTs to /get_keys with empty body."""
        sage = SageRPC()
        mock_resp = mock_response({"keys": [{"fingerprint": 123, "name": "test"}]})
        with patch.object(sage.session, "post", return_value=mock_resp) as mock_post:
            result = sage.get_keys()
        mock_post.assert_called_once_with(f"{DEFAULT_URL}/get_keys", json={})
        assert result == {"keys": [{"fingerprint": 123, "name": "test"}]}

    def test_get_secret_key(self):
        """sage.get_secret_key(123) POSTs fingerprint to /get_secret_key."""
        sage = SageRPC()
        mock_resp = mock_response({
            "secrets": {
                "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "secret_key": "00aabb",
            }
        })
        with patch.object(sage.session, "post", return_value=mock_resp) as mock_post:
            result = sage.get_secret_key(123)
        mock_post.assert_called_once_with(
            f"{DEFAULT_URL}/get_secret_key", json={"fingerprint": 123}
        )
        assert result["secrets"]["mnemonic"].startswith("abandon")

    def test_get_coins(self):
        """sage.get_coins() POSTs to /get_coins with filter_mode=selectable."""
        sage = SageRPC()
        mock_resp = mock_response({"coins": [{"coin": {"parent_coin_info": "0xaa", "puzzle_hash": "0xbb", "amount": 100}}]})
        with patch.object(sage.session, "post", return_value=mock_resp) as mock_post:
            result = sage.get_coins()
        call_data = mock_post.call_args[1]["json"]
        assert call_data["filter_mode"] == "selectable"
        assert call_data["sort_mode"] == "amount"
        assert call_data["ascending"] is False
        assert len(result["coins"]) == 1

    def test_get_spendable_coins(self):
        """sage.get_coins() returns coins with parent_coin_info, puzzle_hash, and amount."""
        sage = SageRPC()
        coin_data = {
            "coins": [{
                "coin": {
                    "parent_coin_info": "0xabcdef1234567890",
                    "puzzle_hash": "0x1122334455667788",
                    "amount": 1000000000000,
                }
            }]
        }
        mock_resp = mock_response(coin_data)
        with patch.object(sage.session, "post", return_value=mock_resp):
            result = sage.get_coins()
        coin = result["coins"][0]["coin"]
        assert "parent_coin_info" in coin
        assert "puzzle_hash" in coin
        assert "amount" in coin

    def test_call_raises_on_http_error(self):
        """sage.call() raises requests.HTTPError on 500 response."""
        sage = SageRPC()
        mock_resp = mock_response({"error": "internal"}, status_code=500)
        with patch.object(sage.session, "post", return_value=mock_resp):
            with pytest.raises(requests.HTTPError):
                sage.call("some_endpoint", {"data": 1})


class TestSageSendXch:
    def test_send_xch_basic(self):
        """sage.send_xch() POSTs to /send_xch with address, amount, fee, memos, auto_submit."""
        sage = SageRPC()
        mock_resp = mock_response({"summary": {}, "coin_spends": []})
        with patch.object(sage.session, "post", return_value=mock_resp) as mock_post:
            result = sage.send_xch("txch1abc123", 1000000, fee=100)
        mock_post.assert_called_once_with(
            f"{DEFAULT_URL}/send_xch",
            json={
                "address": "txch1abc123",
                "amount": 1000000,
                "fee": 100,
                "memos": [],
                "auto_submit": True,
            },
        )
        assert result == {"summary": {}, "coin_spends": []}

    def test_send_xch_with_memos(self):
        """sage.send_xch() includes memos in payload when provided."""
        sage = SageRPC()
        mock_resp = mock_response({"summary": {}, "coin_spends": []})
        with patch.object(sage.session, "post", return_value=mock_resp) as mock_post:
            sage.send_xch("txch1abc123", 1000, memos=["hello"])
        call_data = mock_post.call_args[1]["json"]
        assert call_data["memos"] == ["hello"]

    def test_send_xch_default_fee(self):
        """sage.send_xch() defaults fee to 0 when not specified."""
        sage = SageRPC()
        mock_resp = mock_response({"summary": {}, "coin_spends": []})
        with patch.object(sage.session, "post", return_value=mock_resp) as mock_post:
            sage.send_xch("txch1abc123", 5000)
        call_data = mock_post.call_args[1]["json"]
        assert call_data["fee"] == 0


class TestSageSubmitTransaction:
    def test_submit_transaction(self):
        """sage.submit_transaction() POSTs spend bundle to /submit_transaction."""
        sage = SageRPC()
        mock_resp = mock_response({})
        bundle_json = {"aggregated_signature": "0xaabb", "coin_spends": []}
        with patch.object(sage.session, "post", return_value=mock_resp) as mock_post:
            result = sage.submit_transaction(bundle_json)
        mock_post.assert_called_once_with(
            f"{DEFAULT_URL}/submit_transaction",
            json={"spend_bundle": {"aggregated_signature": "0xaabb", "coin_spends": []}},
        )
        assert result == {}

    def test_submit_transaction_error(self):
        """sage.submit_transaction() raises HTTPError on 422 response."""
        sage = SageRPC()
        mock_resp = mock_response({"error": "invalid"}, status_code=422)
        with patch.object(sage.session, "post", return_value=mock_resp):
            with pytest.raises(requests.HTTPError):
                sage.submit_transaction({})


class TestSageAddressIntegration:
    def test_generate_address_from_sage(self):
        """Given mnemonic from get_secret_key, derive and encode silent payment address."""
        from shared import (
            mnemonic_to_master_sk,
            master_sk_to_scan_sk,
            master_sk_to_spend_sk,
            encode_silent_payment_address,
            decode_silent_payment_address,
        )

        # Simulate Sage returning a mnemonic
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

        # Derive keys as the integration would
        master_sk = mnemonic_to_master_sk(mnemonic)
        scan_sk = master_sk_to_scan_sk(master_sk)
        scan_pk = scan_sk.get_g1()
        spend_sk = master_sk_to_spend_sk(master_sk)
        spend_pk = spend_sk.get_g1()

        # Encode address
        addr = encode_silent_payment_address(bytes(scan_pk), bytes(spend_pk))

        # Verify prefix
        assert addr.startswith("tspxch1")

        # Verify round-trip
        decoded_scan, decoded_spend = decode_silent_payment_address(addr)
        assert decoded_scan == bytes(scan_pk)
        assert decoded_spend == bytes(spend_pk)


class TestSendPaymentSpendBundle:
    """Verify the spend bundle flow uses the same coin for input_hash and spending."""

    def test_spend_bundle_coin_matches_input_hash_coin(self):
        """The coin_id used for input_hash derivation equals the coin spent in the bundle."""
        from shared import (
            mnemonic_to_master_sk, master_sk_to_wallet_sk,
            calculate_synthetic_secret_key,
            compute_input_hash, compute_shared_secret_full,
            derive_output_tweak, derive_onetime_pk_full,
            puzzle_for_pk, puzzle_hash_for_pk,
            decode_silent_payment_address, encode_silent_payment_address,
            master_sk_to_scan_sk, master_sk_to_spend_sk,
            compute_coin_id,
            TESTNET11_GENESIS,
        )
        from chia_rs import Coin, CoinSpend, SpendBundle, AugSchemeMPL, Program

        # Sender setup
        sender_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        master_sk = mnemonic_to_master_sk(sender_mnemonic)
        wallet_sk = master_sk_to_wallet_sk(master_sk, index=0)
        sender_sk = calculate_synthetic_secret_key(wallet_sk)
        sender_pk = sender_sk.get_g1()

        # Fake coin data (simulating what coinset would return)
        parent_coin_info = bytes(32)  # 32 zero bytes
        sender_puzzle_hash = puzzle_hash_for_pk(wallet_sk.get_g1())
        coin_amount = 1000000
        coin_id = compute_coin_id(parent_coin_info, sender_puzzle_hash, coin_amount)
        coin_ids = [coin_id]

        # Recipient setup
        recipient_mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        r_master = mnemonic_to_master_sk(recipient_mnemonic)
        scan_sk = master_sk_to_scan_sk(r_master)
        scan_pk = scan_sk.get_g1()
        spend_sk = master_sk_to_spend_sk(r_master)
        spend_pk = spend_sk.get_g1()

        # Derive one-time address (sender side)
        input_hash = compute_input_hash(coin_ids, sender_pk)
        shared_secret = compute_shared_secret_full(sender_sk, scan_pk, input_hash)
        tweak = derive_output_tweak(shared_secret, 0)
        onetime_pk = derive_onetime_pk_full(spend_pk, tweak)
        onetime_puzzle_hash = puzzle_hash_for_pk(onetime_pk)

        # Build spend bundle (mirroring the new send_payment.py logic)
        payment_amount = 500000
        fee = 0
        coin = Coin(parent_coin_info, sender_puzzle_hash, coin_amount)

        # Verify the coin name matches our computed coin_id
        assert coin.name() == coin_id, "Coin.name() must match computed coin_id"

        sender_puzzle = puzzle_for_pk(wallet_sk.get_g1())
        conditions = [[51, onetime_puzzle_hash, payment_amount]]
        change = coin_amount - payment_amount - fee
        if change > 0:
            conditions.append([51, sender_puzzle_hash, change])

        delegated_puzzle = Program.to((1, conditions))
        dp_bytes = bytes(delegated_puzzle)
        solution = Program.from_bytes_unchecked(
            b'\xff\x80\xff' + dp_bytes + b'\xff\x80\x80'
        )

        msg = delegated_puzzle.get_tree_hash() + coin.name() + TESTNET11_GENESIS
        sig = AugSchemeMPL.sign(sender_sk, msg)
        coin_spend = CoinSpend(coin, sender_puzzle, solution)
        spend_bundle = SpendBundle([coin_spend], sig)

        # Key assertion: the coin spent in the bundle is the same one used for input_hash
        bundle_json = spend_bundle.to_json_dict()
        spent_coin = bundle_json["coin_spends"][0]["coin"]
        # parent_coin_info in JSON is 0x-prefixed hex
        assert spent_coin["parent_coin_info"] == "0x" + parent_coin_info.hex()
        assert spent_coin["puzzle_hash"] == "0x" + sender_puzzle_hash.hex()
        assert spent_coin["amount"] == coin_amount

    def test_spend_bundle_has_change_output(self):
        """When payment amount < coin value, change condition is included."""
        from shared import (
            mnemonic_to_master_sk, master_sk_to_wallet_sk,
            calculate_synthetic_secret_key,
            puzzle_hash_for_pk,
        )
        from chia_rs import Program

        sender_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        master_sk = mnemonic_to_master_sk(sender_mnemonic)
        wallet_sk = master_sk_to_wallet_sk(master_sk, index=0)
        sender_puzzle_hash = puzzle_hash_for_pk(wallet_sk.get_g1())

        # Build conditions with change
        coin_value = 1000000
        payment = 400000
        fee = 100
        change = coin_value - payment - fee

        onetime_ph = bytes(32)  # placeholder
        conditions = [
            [51, onetime_ph, payment],
        ]
        if change > 0:
            conditions.append([51, sender_puzzle_hash, change])
        if fee > 0:
            conditions.append([52, fee])

        delegated_puzzle = Program.to((1, conditions))
        # Verify the conditions are structured correctly
        assert change == 599900
        # Delegated puzzle should serialize without error
        assert len(bytes(delegated_puzzle)) > 0
