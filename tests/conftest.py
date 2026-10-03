"""
Session-scoped freshness gate for the SDK test suite.

Purpose: make a stale, wrong-venv, or wrong-commit `chia_wallet_sdk` wheel
*structurally incapable* of silently green-lighting old behavior. Before ANY test
runs, hard-fail unless the loaded native extension is provably the wheel built
from the SDK commit pinned in BUILD.md, installed into the active venv.

The three assertions (any failure aborts the whole suite):
  (1) chia_wallet_sdk.__file__   resolves under the active venv
  (2) sys.executable             resolves under the active venv
  (3) the wheel's surfaced SDK commit short-hash contains PINNED_SDK_COMMIT

How the wheel surfaces its commit hash: for the build, the pyo3 crate version is
stamped with a PEP 440 local version `<semver>+g<short commit hash>`, so
`importlib.metadata.version("chia_wallet_sdk")` returns that string. The
`+g<hash>` local segment is the SDK commit the wheel compiles. We parse it here.
(The plain semver carries no hash, so the version metadata has to be made
hash-bearing for the build — a temporary, uncommitted edit of `pyo3/Cargo.toml`;
see BUILD.md.)

This gate is deliberately cheap: it does NOT trigger a rebuild. On a no-rebuild
test run, assertion (3) still catches a stale .so via the embedded version hash.
"""

import sys
import importlib.metadata
from pathlib import Path

import pytest
import chia_wallet_sdk

# The active virtual environment (whatever interpreter is running the suite).
VENV = Path(sys.prefix).resolve()

# SDK commit short-hash embedded in the wheel version's PEP 440 local segment.
# MUST match the "SDK source pin" table in BUILD.md; update BOTH when the SDK is
# re-pinned.
PINNED_SDK_COMMIT = "gd4b8bebe"


def _wheel_commit() -> str:
    """Return the SDK commit short-hash surfaced by the loaded wheel.

    Reads `importlib.metadata.version("chia_wallet_sdk")`, which the build makes
    hash-bearing via a PEP 440 local-version segment (`<semver>+g<hash>`).
    Returns the full version string; the caller asserts PINNED_SDK_COMMIT is a
    substring (the `+g<hash>` part).
    """
    try:
        version = importlib.metadata.version("chia_wallet_sdk")
    except importlib.metadata.PackageNotFoundError as exc:  # pragma: no cover
        raise AssertionError(
            "chia_wallet_sdk metadata not found; the wheel is not installed in "
            "this venv. Build it per BUILD.md."
        ) from exc
    if "+" not in version:
        raise AssertionError(
            f"chia_wallet_sdk version {version!r} carries no +g<hash> local segment. "
            "The pyo3 Cargo.toml version stamp (PEP 440 local version) that bakes the "
            "commit short-hash was not applied for the build, or the wheel is stale. "
            "Rebuild per BUILD.md."
        )
    return version


@pytest.fixture(scope="session", autouse=True)
def _freshness_gate():
    """Hard-fail the entire suite unless the wheel is fresh and venv-contained."""
    wheel_file = Path(chia_wallet_sdk.__file__).resolve()
    if VENV not in wheel_file.parents:
        pytest.exit(
            f"FRESHNESS GATE: chia_wallet_sdk is not installed in the active venv.\n"
            f"  wheel __file__ = {wheel_file}\n"
            f"  expected under = {VENV}\n"
            f"Build it into the active venv: see BUILD.md.",
            returncode=1,
        )

    # Resolve the interpreter's directory, not the interpreter itself: in a default
    # venv `bin/python` is a symlink to the base interpreter outside the venv.
    exe = Path(sys.executable)
    exe_dir = exe.parent.resolve()
    if VENV not in (exe_dir, *exe_dir.parents):
        pytest.exit(
            f"FRESHNESS GATE: tests are not running under the active venv interpreter.\n"
            f"  sys.executable = {exe}\n"
            f"  expected under = {VENV}\n"
            f"Run with {VENV}/bin/python -m pytest ...",
            returncode=1,
        )

    surfaced = _wheel_commit()
    if PINNED_SDK_COMMIT not in surfaced:
        pytest.exit(
            f"FRESHNESS GATE: stale/wrong wheel. The loaded wheel's surfaced SDK "
            f"commit does not match the pin in BUILD.md.\n"
            f"  wheel version     = {surfaced!r}\n"
            f"  PINNED_SDK_COMMIT = {PINNED_SDK_COMMIT!r}\n"
            f"Rebuild per BUILD.md (and update PINNED_SDK_COMMIT + BUILD.md "
            f"together if the SDK was re-pinned).",
            returncode=1,
        )

    yield
