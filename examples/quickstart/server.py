"""LocuGard Quickstart HTTPS Server with the built-in Web UI, native client API, and service introspection API.

Demonstrates:
- HTTPS + __Host-locugard_sid cookie (HttpOnly; Secure; SameSite=Lax)
- Built-in Web UI (include_ui=True) with zero localStorage token usage
- Native client HTTPS endpoints (/auth/app/*) and service introspection/revocation stream (/api/service/*)
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if (_REPO_ROOT / "locugard").is_dir() and str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import uvicorn

from locugard.auth_channels import AuthChannels
from locugard.auth_permissions import AuthPermissionsBridge
from locugard.auth_service import AuthService
from locugard.auth_store import AuthStore
from locugard.permissions_adapter import LocalPermissions
from locugard.web_server import create_web_app

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("LOCUGARD_DATA_DIR", str(BASE_DIR / "data")))
SECRETS_DIR = Path(os.environ.get("LOCUGARD_SECRETS_DIR", str(BASE_DIR / "secrets")))
RP_ID = os.environ.get("LOCUGARD_RP_ID", "locugard.home.arpa")
HOST = os.environ.get("LOCUGARD_HOST", "127.0.0.1")
PORT = int(os.environ.get("LOCUGARD_PORT", "8443"))
ORIGIN = os.environ.get("LOCUGARD_ORIGIN", f"https://{RP_ID}:{PORT}")


def _split_csv_env(name: str) -> list[str]:
    return [x.strip() for x in os.environ.get(name, "").split(",") if x.strip()]


def _load_service_tokens() -> dict[str, dict]:
    tokens: dict[str, dict] = {}
    apogeus_tok = os.environ.get("LOCUGARD_SERVICE_TOKEN_APOGEUS", "").strip()
    if apogeus_tok:
        tokens["apogeus"] = {
            "token": apogeus_tok,
            "audiences": ["apogeus"],
            "redirect_uris": _split_csv_env("LOCUGARD_SSO_REDIRECT_URIS_APOGEUS"),
            "display_name": "Apogeus",
        }
    docalaizer_tok = os.environ.get("LOCUGARD_SERVICE_TOKEN_DOCALAIZER", "").strip()
    if docalaizer_tok:
        tokens["docalaizer"] = {
            "token": docalaizer_tok,
            "audiences": ["docalaizer"],
            "redirect_uris": _split_csv_env("LOCUGARD_SSO_REDIRECT_URIS_DOCALAIZER"),
            "display_name": "Docalaizer",
        }
    return tokens


def build_app():
    store = AuthStore(DATA_DIR, pepper_path=SECRETS_DIR / "auth_pepper.key", allow_create_pepper=False)
    auth = AuthService(store, rp_id=RP_ID, expected_origin=ORIGIN)
    channels = AuthChannels(store, auth)
    perms = LocalPermissions(DATA_DIR)
    bridge = AuthPermissionsBridge(store, auth, perms)
    return create_web_app(
        auth,
        bridge,
        channels=channels,
        include_ui=True,
        service_tokens=_load_service_tokens() or None,
    )


if __name__ == "__main__":
    uvicorn.run(
        build_app(),
        host=HOST,
        port=PORT,
        ssl_certfile=str(SECRETS_DIR / "web_tls.crt"),
        ssl_keyfile=str(SECRETS_DIR / "web_tls.key"),
    )
