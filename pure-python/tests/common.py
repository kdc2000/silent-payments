"""Keys and helpers shared by the test modules.

The CHIP's Test Vectors 1 through 7 treat the recipients' scan and spend
secret keys as GIVEN values: they are not derived from a mnemonic. Tests that
reproduce those vectors take the keys from the constants below. The hardened
derivation of scan and spend keys from a mnemonic is covered separately by
Test Vector 8.
"""

import json
from unittest.mock import MagicMock

from chia_rs import Coin, CoinSpend, PrivateKey, Program

from shared import puzzle_for_pk

# BIP-39 test mnemonic; the sender keys of the vectors are its standard
# wallet keys (m/12381/8444/2/<index>).
TEST_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Recipient of Test Vectors 1, 3, 4, 6, 7 and recipient A of Test Vector 2
RECIPIENT_A_SCAN_SK = PrivateKey.from_bytes(bytes.fromhex(
    "132567e4dec19a4f50d9e9a549f16283dfb5aa4ad1ffdb6a505fcfcc56a690f6"
))
RECIPIENT_A_SPEND_SK = PrivateKey.from_bytes(bytes.fromhex(
    "53d140b312a0e16316314274eb6398e15706d100fe8a754990540febd931b087"
))

# Recipient B of Test Vector 2
RECIPIENT_B_SCAN_SK = PrivateKey.from_bytes(bytes.fromhex(
    "56a3762ba1200ab5a796d3a2af85261f745ee9620e927d0232c18b710cbf22d2"
))
RECIPIENT_B_SPEND_SK = PrivateKey.from_bytes(bytes.fromhex(
    "70fbad8c37b92e585f890bcef5730727d4100584fc9df4bbc9f5e533691d20bf"
))


def output_coin(puzzle_hash: bytes, parent: bytes = b"\x01" * 32, amount: int = 1) -> Coin:
    """An output coin carrying `puzzle_hash`, for handing to the scanner."""
    return Coin(parent, puzzle_hash, amount)


# --- Building blocks without a node ---

def standard_coin(wallet_sk: PrivateKey, parent: bytes, amount: int) -> Coin:
    """A coin locked to the standard puzzle of `wallet_sk`."""
    return Coin(parent, puzzle_for_pk(wallet_sk.get_g1()).get_tree_hash(), amount)


def solution_for_conditions(conditions: list) -> Program:
    """Standard-puzzle solution whose delegated puzzle is the quoted `conditions`."""
    delegated = Program.to((1, conditions))
    return Program.from_bytes_unchecked(b"\xff\x80\xff" + bytes(delegated) + b"\xff\x80\x80")


def standard_spend(coin: Coin, wallet_sk: PrivateKey, conditions: list) -> CoinSpend:
    """Spend of a standard-puzzle coin that outputs `conditions` (an eligible spend)."""
    return CoinSpend(coin, puzzle_for_pk(wallet_sk.get_g1()), solution_for_conditions(conditions))


def conditions_puzzle_spend(coin_parent: bytes, amount: int, conditions: list) -> CoinSpend:
    """Spend of a coin whose puzzle is just `(q . conditions)`: NOT an eligible spend."""
    puzzle = Program.to((1, conditions))
    coin = Coin(coin_parent, puzzle.get_tree_hash(), amount)
    return CoinSpend(coin, puzzle, Program.to(0))


def created_coins(coin_spends: list[CoinSpend]) -> list[Coin]:
    """The additions of a block: every coin created by a CREATE_COIN condition."""
    coins = []
    for coin_spend in coin_spends:
        _, node = coin_spend.puzzle_reveal.run_rust(11_000_000_000, 0, coin_spend.solution)
        while node.pair:
            cond, node = node.pair
            op, args = cond.pair
            if op.atom != b"\x33":  # CREATE_COIN
                continue
            puzzle_hash, rest = args.pair
            amount = int.from_bytes(rest.pair[0].atom, "big", signed=True)
            coins.append(Coin(coin_spend.coin.name(), puzzle_hash.atom, amount))
    return coins


def mock_coinset(blocks: dict[int, list[CoinSpend]], pushed: list | None = None):
    """A `subprocess.run` replacement that serves `blocks` like the coinset CLI.

    blocks maps a height to the coin spends of that block; the additions are
    the coins those spends create. Transactions given to push_tx are appended
    to `pushed`.
    """
    spends = {}       # coin id hex -> (height, CoinSpend)
    created = {}      # coin id hex -> (height, Coin)
    for height, coin_spends in blocks.items():
        for coin_spend in coin_spends:
            spends[coin_spend.coin.name().hex()] = (height, coin_spend)
        for coin in created_coins(coin_spends):
            created[coin.name().hex()] = (height, coin)

    def coin_json(coin: Coin) -> dict:
        return {
            "parent_coin_info": "0x" + coin.parent_coin_info.hex(),
            "puzzle_hash": "0x" + coin.puzzle_hash.hex(),
            "amount": coin.amount,
        }

    def respond(payload: dict, returncode: int = 0):
        return MagicMock(returncode=returncode, stdout=json.dumps(payload), stderr="")

    def run(cmd, **kwargs):
        command, args = cmd[cmd.index("-r") + 1], cmd[cmd.index("-r") + 2:]
        if command == "get_block_records":
            start, end = int(args[0]), int(args[1])
            return respond({"block_records": [
                {"height": h, "timestamp": 1700000000} for h in sorted(blocks) if start <= h < end
            ]})
        if command == "get_additions_and_removals":
            height = int(args[0])
            return respond({
                "additions": [
                    {"coin": coin_json(coin), "coinbase": False}
                    for h, coin in created.values() if h == height
                ],
                "removals": [
                    {"coin": coin_json(cs.coin), "coinbase": False}
                    for h, cs in spends.values() if h == height
                ],
            })
        if command == "get_puzzle_and_solution":
            coin_id = args[0].removeprefix("0x")
            if coin_id not in spends:
                return respond({"success": False})
            _, coin_spend = spends[coin_id]
            return respond({"success": True, "coin_solution": {
                "puzzle_reveal": "0x" + bytes(coin_spend.puzzle_reveal).hex(),
                "solution": "0x" + bytes(coin_spend.solution).hex(),
            }})
        if command == "get_coin_record_by_name":
            coin_id = args[0].removeprefix("0x")
            if coin_id not in created:
                return respond({"success": False})
            height, coin = created[coin_id]
            return respond({"success": True, "coin_record": {
                "coin": coin_json(coin), "coinbase": False,
                "confirmed_block_index": height,
                "spent": coin_id in spends, "spent_block_index": 0,
            }})
        if command == "push_tx":
            if pushed is not None:
                pushed.append(json.loads(args[0]))
            return respond({"success": True, "status": "SUCCESS"})
        return respond({})

    return run
