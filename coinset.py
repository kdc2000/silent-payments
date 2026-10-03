"""Sole boundary for the `coinset` CLI subprocess.

This module consolidates ALL `coinset` CLI invocations (on-chain lookups +
`push_tx` broadcast) into one wrapper returning parsed JSON. It covers the three
distinct call patterns the root scripts need:

  * single hex arg, auto-``0x``, RAISES on failure (coin-id lookups).
  * variadic, ``["-t"]`` base args, NO auto-``0x``, RAISES (height args are plain
    integers).
  * SOFT-FAIL (continue/return on failure) for optional coin sweeps, plus the
    ``push_tx`` broadcast.

Design:
  * ``call(command, *args, optional=...)`` owns the subprocess invocation, the
    JSON parse, the ``-t`` (testnet11) base args, and the raise-vs-sentinel
    error split. It passes args through VERBATIM (stringified only) -- it does
    NOT ``0x``-normalize, so height args from ``get_block_records`` are never
    prefixed.
  * Thin named getters layer the ``success``-flag check on top and pluck the
    relevant sub-dict. Coin-id getters ``0x``-normalize their hex arg; height
    getters do not.
  * Error model: mandatory getters raise ``RuntimeError`` on returncode != 0 OR
    ``success == False``; the ``optional=True`` variant returns ``None`` instead
    of raising, preserving soft-fail sweep semantics.

The subprocess boundary lives here on purpose: an SDK RPC client could replace it
in the future, but the CLI keeps the examples dependency-light.
"""

import json
import subprocess

# Default base args for every coinset invocation (testnet11).
BASE_ARGS = ["-t"]


def call(command, *args, optional=False):
    """Invoke the coinset CLI and return the parsed JSON response.

    Args are stringified and passed VERBATIM -- no ``0x`` normalization happens
    here (that is the coin-id getter's job, so height args stay un-prefixed).
    Raises ``RuntimeError`` on a non-zero return code unless ``optional=True``, in
    which case it returns ``None`` (the soft-fail sentinel).
    """
    cmd = ["coinset", *BASE_ARGS, "-r", command, *[str(a) for a in args]]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        if optional:
            return None
        raise RuntimeError(f"coinset error: {result.stderr.strip()}")
    return json.loads(result.stdout)


def _checked(data, key, optional):
    """Layer the ``success``-flag check on top of ``call()`` and pluck ``key``.

    ``data`` is ``None`` when ``call(..., optional=True)`` already short-circuited
    on a non-zero return code. A ``success == False`` body is the second failure
    mode: mandatory getters raise; optional getters return the ``None`` sentinel.
    """
    if data is None:
        return None
    if not data.get("success"):
        if optional:
            return None
        raise RuntimeError(f"coinset call failed: {data}")
    return data[key]


def _hex_arg(arg):
    """0x-normalize a hex coin-id / puzzle-hash arg."""
    return arg if arg.startswith("0x") else "0x" + arg


# ---------------------------------------------------------------------------
# Named getters
#
# Coin-id / puzzle-hash getters 0x-normalize their hex arg. Height getters
# (get_block_records) pass plain integer args through call() verbatim -- they are
# NEVER 0x-prefixed. Mandatory getters raise; optional getters return the None
# sentinel (soft-fail).
# ---------------------------------------------------------------------------


def get_coin_record(coin_id, optional=False):
    """Look up a coin record by name. CLI command: get_coin_record_by_name.

    Mandatory by default (raises on failure). ``optional=True`` returns ``None``
    on failure -- for per-coin soft-fail sweeps.
    """
    data = call("get_coin_record_by_name", _hex_arg(coin_id), optional=optional)
    return _checked(data, "coin_record", optional)


def get_puzzle_and_solution(coin_id, optional=False):
    """Fetch the puzzle reveal + solution for a spent coin (raises by default)."""
    data = call("get_puzzle_and_solution", _hex_arg(coin_id), optional=optional)
    return _checked(data, "coin_solution", optional)


def get_coin_records_by_puzzle_hash(puzzle_hash, optional=True):
    """Sweep coin records for a puzzle hash.

    Defaults to ``optional=True`` for non-fatal sweep semantics (return ``[]`` on
    failure rather than raising).
    """
    data = call("get_coin_records_by_puzzle_hash", _hex_arg(puzzle_hash), optional=optional)
    return _checked(data, "coin_records", optional)


def get_blockchain_state():
    """Return the full parsed blockchain-state dict (raises on failure).

    No 0x-normalization. Caller plucks ["blockchain_state"]["peak"]["height"], so
    this is intentionally NOT pre-plucked.
    """
    return call("get_blockchain_state")


def get_block_records(start, end):
    """Return the ``block_records`` list for [start, end). Heights pass VERBATIM.

    ``start`` / ``end`` are block heights -- call() stringifies them but NEVER
    0x-prefixes them. The get_block_records response carries no ``success`` flag,
    so this plucks ``["block_records"]`` directly. call() already raised on a
    non-zero return code.
    """
    data = call("get_block_records", start, end)
    return data.get("block_records", []) if data is not None else []


def get_additions_and_removals(height):
    """Return ``{"additions": [...], "removals": [...]}`` for a block height.

    ``height`` is a block height -- call() stringifies it but NEVER 0x-prefixes
    it (no ``_hex_arg``). The get_additions_and_removals response carries no
    ``success`` flag, so this plucks ``additions``/``removals`` directly (call()
    already raised on a non-zero return code -- this is a mandatory getter).
    """
    data = call("get_additions_and_removals", height)
    if data is None:
        return {"additions": [], "removals": []}
    return {
        "additions": data.get("additions", []),
        "removals": data.get("removals", []),
    }


def push_tx(wire_dict):
    """Broadcast a spend bundle. The wire dict is json.dumps-ed as the single arg.

    ``wire_dict`` is the output of sdk_adapter.sdk_bundle_to_wire_dict; the
    send/spend scripts wire to this. Equivalent to
    ``subprocess.run(["coinset","-t","-r","push_tx", json.dumps(...)])``.
    """
    return call("push_tx", json.dumps(wire_dict))
