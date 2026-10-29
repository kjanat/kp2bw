"""Create an organization in the disposable Vaultwarden test account.

Uses the fixture's PBKDF2 account and the server API because bw cannot create
organizations. All generated keys are ephemeral; nothing is written to disk.
"""

import base64
import hashlib
import hmac
import os
import ssl
import uuid
from pathlib import Path

import httpx
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Hash import SHA1
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.Padding import pad


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def create_scope_organization(
    server: str, cert: Path, email: str, password: str
) -> str:
    """Provision one synthetic org and its initial collection via real APIs."""
    with httpx.Client(
        base_url=server, verify=ssl.create_default_context(cafile=cert)
    ) as api:
        prelogin = api.post("/identity/accounts/prelogin", json={"email": email})
        prelogin.raise_for_status()
        kdf = prelogin.json()
        if kdf["kdf"] != 0:
            raise AssertionError("Scope fixture requires its PBKDF2 test account")
        master = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), email.lower().encode(), kdf["kdfIterations"]
        )
        password_hash = _b64(
            hashlib.pbkdf2_hmac("sha256", master, password.encode(), 1)
        )
        login = api.post(
            "/identity/connect/token",
            data={
                "grant_type": "password",
                "username": email,
                "password": password_hash,
                "scope": "api offline_access",
                "client_id": "cli",
                "deviceType": "8",
                "deviceIdentifier": str(uuid.uuid4()),
                "deviceName": "kp2bw-scope-fixture",
            },
        )
        login.raise_for_status()
        api.headers["Authorization"] = f"Bearer {login.json()['access_token']}"
        profile = api.get("/api/accounts/profile")
        profile.raise_for_status()
        keys = api.get(f"/api/users/{profile.json()['id']}/public-key")
        keys.raise_for_status()
        public_key = RSA.import_key(base64.b64decode(keys.json()["publicKey"]))
        org_key = os.urandom(64)
        encrypted_key = "4." + _b64(
            PKCS1_OAEP.new(public_key, hashAlgo=SHA1).encrypt(org_key)
        )
        iv = os.urandom(16)
        # PyCryptodome's unrelated CTR overload has an untyped counter dict.
        ciphertext = AES.new(org_key[:32], AES.MODE_CBC, iv).encrypt(  # pyright: ignore[reportUnknownMemberType]
            pad(b"Scope A", 16)
        )
        mac = hmac.digest(org_key[32:], iv + ciphertext, "sha256")
        collection_name = "2." + "|".join(map(_b64, (iv, ciphertext, mac)))
        response = api.post(
            "/api/organizations",
            json={
                "name": "kp2bw scope regression",
                "billingEmail": email,
                "collectionName": collection_name,
                "key": encrypted_key,
                "planType": 0,
            },
        )
        response.raise_for_status()
        org_id = response.json()["id"]
        if not isinstance(org_id, str):
            raise TypeError("Missing scope organization ID")
        return org_id
