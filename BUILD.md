# BUILD.md — building the `chia_wallet_sdk` wheel for the SDK examples

The example scripts at the top level of this repository call the
[chia-wallet-sdk](https://github.com/xch-dev/chia-wallet-sdk) through its Python
(pyo3) bindings. Silent-payment support is not yet in a `chia-wallet-sdk` release
on PyPI, so the wheel has to be built from source and installed into your
virtualenv. This document describes that build and the freshness gate the tests
use to make sure they run against the right wheel.

`pure-python/` and `rust-scanner/` do not use this wheel and need none of this.

## Prerequisites

- **Rust**, installed via `rustup`. The SDK tree pins its toolchain in
  `rust-toolchain.toml`; `rustup` selects (and, if needed, installs) that version
  automatically, but only when cargo/maturin run from *inside* the SDK tree.
- **A virtualenv** (CPython 3.10 or later) with this repository's
  `requirements.txt` installed. The wheel is `abi3-py38`, so the exact minor
  version does not matter.
- `git` and a C toolchain (`cc`) on `PATH`.
- No chain access is needed to build the wheel or to run the test suite.

## SDK source pin

| Field | Value |
|-------|-------|
| Repository | `https://github.com/kdc2000/chia-wallet-sdk` |
| Branch | `chip-0057-silent-payments` (the head of pull request [xch-dev/chia-wallet-sdk#407](https://github.com/xch-dev/chia-wallet-sdk/pull/407)) |
| Build commit | `d4b8bebe37fdde9d9b4d35bedfea64ae75be4202` |
| Wheel version (the freshness pin) | `0.36.0+gd4b8bebe` |

The short commit hash in the wheel version is the value of `PINNED_SDK_COMMIT` in
`tests/conftest.py` (with its `g` prefix). The commands below read it from there,
so the wheel that gets built is the one the tests expect. **When the SDK is
re-pinned, update this table and `PINNED_SDK_COMMIT` together** — the pin appears
nowhere else.

## Build

Run these from the root of this repository, with the virtualenv activated.

```bash
# 0. The pinned short commit hash, taken from the tests' freshness gate.
PIN=$(sed -n 's/^PINNED_SDK_COMMIT = "g\(.*\)"$/\1/p' tests/conftest.py)

# 1. Clone the SDK and check out the pinned commit of the branch.
git clone --branch chip-0057-silent-payments https://github.com/kdc2000/chia-wallet-sdk
cd chia-wallet-sdk
git checkout --detach "$PIN"
git status --porcelain                      # -> (nothing): the tree is clean

# 2. Install the build front-end into the virtualenv.
python -m pip install "maturin>=1.8,<2.0"

# 3. Stamp the pyo3 crate version with the commit: <version> -> <version>+g<commit>.
#    pyo3/pyproject.toml declares dynamic = ["version"], so maturin takes the
#    wheel version from [package].version in pyo3/Cargo.toml. The stamp is what
#    lets the tests' freshness gate tell which commit a wheel was built from. It
#    is a local, uncommitted edit.
BASE_VERSION=$(sed -n 's/^version = "\([^"+]*\)"$/\1/p' pyo3/Cargo.toml)
sed -i "s/^version = \"$BASE_VERSION\"$/version = \"$BASE_VERSION+g$PIN\"/" pyo3/Cargo.toml

# 4. Build and install into the active virtualenv. Run it from inside the SDK
#    tree so that rust-toolchain.toml selects the pinned Rust version.
(cd pyo3 && python -m maturin develop --release)

# 5. Revert the stamp (and Cargo.lock, if cargo rewrote the crate version in it).
git checkout -- pyo3/Cargo.toml Cargo.lock
cd ..
```

Notes:

- `maturin develop` installs into the *current* virtualenv (`VIRTUAL_ENV`). It is
  invoked as `python -m maturin` so that the virtualenv's own maturin is used. To
  build without activating the virtualenv, run
  `VIRTUAL_ENV=<venv> <venv>/bin/python -m maturin develop --release`.
- The `--release` profile uses LTO; expect a multi-minute compile. Do not switch
  to a debug build: the tests should exercise the release artifact.
- `sed -i` as written is GNU sed. On macOS use `sed -i ''`.

A known-good combination of tools for this build:

| Tool | Version |
|------|---------|
| maturin | `1.13.3` |
| `rustc` (selected by the SDK's `rust-toolchain.toml`) | `1.95.0` |
| pyo3 | `0.23.5` (`abi3-py38`) |
| CPython | `3.10.12` |

## Verify

```bash
python -c "import chia_wallet_sdk, chia_rs, sys; print(chia_wallet_sdk.__file__, sys.executable)"
```

Both printed paths must be under your virtualenv. This also shows that
`chia_wallet_sdk` loads in the same process as `chia_rs` (the examples use both).

```bash
python -c "import importlib.metadata as m; print(m.version('chia_wallet_sdk'))"
```

This must print the wheel version of the table above. A wheel built without the
stamp of step 3 prints the plain version with no `+g<commit>` part, and the test
suite will refuse to run against it.

Then run the tests from the root of this repository:

```bash
python -m pytest
```

## Freshness gate (what `tests/conftest.py` asserts, and why)

A session-scoped, `autouse` fixture stops the **entire** top-level suite before any
test runs unless all three hold:

1. `chia_wallet_sdk.__file__` is under the active virtualenv (`sys.prefix`).
2. The running interpreter (`sys.executable`) is in the active virtualenv.
3. `importlib.metadata.version("chia_wallet_sdk")` contains `PINNED_SDK_COMMIT`.

**Why:** the examples track an SDK branch that is still under review. A stale
wheel, a wheel from another environment, or a wheel built from a different commit
would otherwise make the tests pass or fail for reasons that have nothing to do
with this repository. The gate is cheap (it never rebuilds anything) and turns
that situation into one clear message.

**How the commit is surfaced:** the branch itself carries the plain crate version.
Step 3 of the build stamps it with the PEP 440 local version `+g<commit>`, maturin
bakes it into the wheel metadata, and the gate looks for the `g<commit>` segment
in `importlib.metadata.version("chia_wallet_sdk")`.

## K_MAX note

`K_MAX = 2400` in `shared.py` is the CHIP-0057 `K_max` ("K_max: Maximum Outputs
Per Spend Group"). It is a limit shared by both sides: a sender MUST NOT create
more than `K_max` outputs for one scan key in a spend group, and a scanner MUST
stop at `k == K_max`, so that all scanners find the same set of payments.

The scan path passes `shared.K_MAX` explicitly as `k_max` to the SDK's
`scan_from_tweaks`. The SDK caps the scan at 2400 whatever value it is given
(`tests/test_chip0057_vectors.py::test_k_max_is_capped_at_the_chip_value` pins
that). The wheel does not export the SDK's constant to Python, which is why the
value lives in `shared.py`.
