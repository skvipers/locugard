"""LocuGard Quickstart Setup: generates a local Root CA, server TLS cert, persistent pepper, and SQLite DB.

Usage:
    python examples/quickstart/setup.py --rp-id locugard.home.arpa --lan-cidr 192.168.1.0/24
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import os
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if (_REPO_ROOT / "locugard").is_dir() and str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from locugard.auth_store import AuthStore, load_or_create_pepper


def generate_local_certs(secrets_dir: Path, rp_id: str, lan_ip: str = "") -> tuple[Path, Path, Path]:
    secrets_dir.mkdir(parents=True, exist_ok=True)
    ca_key_p = secrets_dir / "locugard-local-ca.key"
    ca_crt_p = secrets_dir / "locugard-local-ca.crt"
    srv_key_p = secrets_dir / "web_tls.key"
    srv_crt_p = secrets_dir / "web_tls.crt"

    if ca_crt_p.exists() and srv_crt_p.exists() and srv_key_p.exists():
        return ca_crt_p, srv_crt_p, srv_key_p

    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_sub = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "LocuGard Local Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LocuGard Self-Hosted"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_sub)
        .issuer_name(ca_sub)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1095))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    srv_key = ec.generate_private_key(ec.SECP256R1())
    srv_sub = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, rp_id)])
    san_list: list[x509.GeneralName] = [
        x509.DNSName(rp_id),
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]
    if lan_ip:
        san_list.append(x509.IPAddress(ipaddress.ip_address(lan_ip)))

    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(srv_sub)
        .issuer_name(ca_sub)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    ca_key_p.write_bytes(ca_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ca_crt_p.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    srv_key_p.write_bytes(srv_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    srv_crt_p.write_bytes(srv_cert.public_bytes(serialization.Encoding.PEM))
    return ca_crt_p, srv_crt_p, srv_key_p


def restrict_secret_permissions(path: Path) -> None:
    if not path.exists():
        return
    if os.name == "nt":
        user = os.environ.get("USERNAME", "")
        if user:
            subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:(R,W)"],
                check=False,
                capture_output=True,
            )
    else:
        os.chmod(path, 0o600)


def main() -> None:
    base_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Initialize LocuGard quickstart certs, pepper, and SQLite DB.")
    parser.add_argument("--rp-id", default=os.environ.get("LOCUGARD_RP_ID", "locugard.home.arpa"))
    parser.add_argument("--lan-ip", default="", help="Optional LAN IPv4/IPv6 to add to certificate SAN")
    parser.add_argument("--lan-cidr", action="append", default=[], help="Optional trusted LAN CIDR (repeatable)")
    parser.add_argument("--secrets-dir", default=str(base_dir / "secrets"))
    parser.add_argument("--data-dir", default=str(base_dir / "data"))
    args = parser.parse_args()

    secrets_dir = Path(args.secrets_dir)
    data_dir = Path(args.data_dir)

    ca_crt, srv_crt, srv_key = generate_local_certs(secrets_dir, args.rp_id, args.lan_ip)
    pepper_path = secrets_dir / "auth_pepper.key"
    load_or_create_pepper(data_dir, pepper_path=pepper_path, allow_create=True)

    for secret_file in (secrets_dir / "locugard-local-ca.key", srv_key, pepper_path):
        restrict_secret_permissions(secret_file)

    store = AuthStore(data_dir, pepper_path=pepper_path, allow_create_pepper=False)
    allowed_networks = ["127.0.0.0/8"] + list(args.lan_cidr)
    store.update_server_policy(allowed_networks=allowed_networks)

    print("QUICKSTART_READY")
    print(f"  RP ID:   {args.rp_id}")
    print(f"  CA cert: {ca_crt}  (install in client trust store)")
    print(f"  TLS crt: {srv_crt}")
    print(f"  TLS key: {srv_key}")
    print(f"  Pepper:  {pepper_path}  (keep on ACL-capable filesystem: NTFS/ext4/APFS)")
    print(f"  SQLite:  {store.db_path}")


if __name__ == "__main__":
    main()
