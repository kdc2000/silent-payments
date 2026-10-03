"""Sage wallet RPC client for Chia silent payments."""

import os
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_URL = "https://127.0.0.1:9257"
DEFAULT_DATA_DIR = os.path.expanduser("~/.local/share/com.rigidnetwork.sage")
DEFAULT_CERT = os.path.join(DEFAULT_DATA_DIR, "ssl", "wallet.crt")
DEFAULT_KEY = os.path.join(DEFAULT_DATA_DIR, "ssl", "wallet.key")


class SageRPC:
    """HTTPS client for Sage wallet RPC with TLS client certificate auth."""

    def __init__(self, url=None, cert_path=None, key_path=None):
        self.url = url or os.environ.get("SAGE_RPC_URL", DEFAULT_URL)
        cert = cert_path or os.environ.get("SAGE_CERT_PATH", DEFAULT_CERT)
        key = key_path or os.environ.get("SAGE_KEY_PATH", DEFAULT_KEY)
        self.session = requests.Session()
        self.session.cert = (cert, key)
        self.session.verify = False  # Self-signed cert

    def call(self, endpoint: str, data: dict | None = None) -> dict:
        resp = self.session.post(f"{self.url}/{endpoint}", json=data or {})
        resp.raise_for_status()
        return resp.json()

    def get_keys(self) -> dict:
        return self.call("get_keys")

    def login(self, fingerprint: int) -> dict:
        return self.call("login", {"fingerprint": fingerprint})

    def get_secret_key(self, fingerprint: int) -> dict:
        return self.call("get_secret_key", {"fingerprint": fingerprint})

    def get_coins(self, limit: int = 50, offset: int = 0) -> dict:
        return self.call("get_coins", {
            "offset": offset,
            "limit": limit,
            "sort_mode": "amount",
            "filter_mode": "selectable",
            "ascending": False,
        })

    def get_sync_status(self) -> dict:
        return self.call("get_sync_status")

    def send_xch(self, address: str, amount: int, fee: int = 0,
                 memos: list[str] | None = None) -> dict:
        return self.call("send_xch", {
            "address": address,
            "amount": amount,
            "fee": fee,
            "memos": memos or [],
            "auto_submit": True,
        })

    def submit_transaction(self, spend_bundle_json: dict) -> dict:
        return self.call("submit_transaction", {
            "spend_bundle": spend_bundle_json,
        })
