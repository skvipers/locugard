"""Локальная консоль управления LocuGard (P0 bootstrap, консольное подтверждение и P10 аварийное восстановление)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .auth_channels import AuthChannels
from .auth_service import AuthError, AuthService
from .auth_store import AuthStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m locugard.auth_cli")
    parser.add_argument("--data-dir", required=True, help="Путь к каталогу данных")
    parser.add_argument("--pepper-path", default="", help="Путь к файлу постоянного 256-битного pepper")
    parser.add_argument("--rp-id", default="locugard.home.arpa")
    parser.add_argument("--origin", default="https://locugard.home.arpa:8443")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="Показать статус инициализации владельца")

    p_begin = sub.add_parser("bootstrap-begin", help="Начать создание первого владельца")
    p_begin.add_argument("--name", required=True)

    p_done = sub.add_parser("bootstrap-complete", help="Завершить создание первого владельца")
    p_done.add_argument("--challenge-id", required=True)
    p_done.add_argument("--name", required=True)
    p_done.add_argument("--device-name", required=True)
    p_done.add_argument("--credential-json", required=True)
    p_done.add_argument("--hardware-binding", action="store_true", help="Пометить ключ как аппаратно привязанный (FIDO2)")
    p_done.add_argument("--confirm-fingerprint", action="store_true", help="Подтвердить отпечаток без интерактивного ввода")

    p_ver = sub.add_parser("console-verify", help="Выдать одноразовое второе подтверждение с локальной консоли (режимы 3–4)")
    p_ver.add_argument("--account-id", required=True)
    p_ver.add_argument("--purpose", required=True)
    p_ver.add_argument("--target-digest", default=None)

    p_rec = sub.add_parser("console-recover", help="Аварийное восстановление owner с локальной консоли (P10)")
    p_rec.add_argument("--account-id", required=True)
    p_rec.add_argument("--device-name", required=True)
    p_rec.add_argument("--pubkey-pem", required=True, help="Путь к PEM-файлу нового публичного ключа")
    p_rec.add_argument("--hardware-binding", action="store_true")

    args = parser.parse_args(argv)
    pepper_p = Path(args.pepper_path) if args.pepper_path else None
    store = AuthStore(Path(args.data_dir), pepper_path=pepper_p)
    auth = AuthService(store, rp_id=args.rp_id, expected_origin=args.origin)
    ch = AuthChannels(store, auth)

    try:
        if args.cmd == "status":
            print(json.dumps({"initialized": store.has_active_owner_with_key()}, ensure_ascii=False))
            return 0
        if args.cmd == "bootstrap-begin":
            print(json.dumps(auth.bootstrap_owner_begin(args.name), ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "bootstrap-complete":
            payload = json.loads(Path(args.credential_json).read_text(encoding="utf-8"))
            if not args.confirm_fingerprint:
                ans = input(f"Подтвердить активацию первого owner '{args.name}' ({args.device_name})? [y/N]: ").strip().lower()
                if ans != "y":
                    print(json.dumps({"error": "cancelled_by_admin"}, ensure_ascii=False), file=sys.stderr)
                    return 1
            out = auth.bootstrap_owner_complete(
                challenge_id=args.challenge_id,
                display_name=args.name,
                device_name=args.device_name,
                credential_payload=payload,
                hardware_binding=args.hardware_binding,
            )
            print(json.dumps(out, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "console-verify":
            ver_id = auth.create_console_verification(args.account_id, args.purpose, target_digest=args.target_digest)
            print(json.dumps({"verification_id": ver_id}, ensure_ascii=False))
            return 0
        if args.cmd == "console-recover":
            pub_pem = Path(args.pubkey_pem).read_bytes()
            out = ch.console_recover_owner(
                account_id=args.account_id,
                new_public_key_pem=pub_pem,
                device_name=args.device_name,
                hardware_binding=args.hardware_binding,
            )
            print(json.dumps(out, ensure_ascii=False, indent=2))
            return 0
    except AuthError as e:
        print(json.dumps({"error": e.code}, ensure_ascii=False), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
