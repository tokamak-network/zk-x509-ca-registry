#!/usr/bin/env python3
"""
Admin CLI for zk-x509-ca-registry.

Service administrators use this tool to:
  - Register a new service (init)
  - Add a CA certificate (add-ca)
  - Remove a CA certificate (remove-ca)
  - Sign to prove admin identity (sign) — includes operation type + timestamp
  - Verify an admin signature (verify) — checks 24h expiry
  - List services and CAs (list)

Signature format follows tokamak-rollup-metadata-repository pattern:
  - Structured message with chain_id, registry, admin, operation, timestamp
  - 24-hour signature expiry enforcement
  - Operation type embedded in signature for consistency validation
"""

import argparse
import binascii
import hashlib
import json
import re
import shutil
import sys
import time
from datetime import date, datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


REPO_ROOT = Path(__file__).parent.parent
SERVICES_DIR = REPO_ROOT / "services"
SIGNATURE_EXPIRY_SECONDS = 86400  # 24 hours

VALID_OPERATIONS = ("register", "add-ca", "remove-ca", "update")


def get_service_dir(chain_id: str, registry: str) -> Path:
    """Get service directory path."""
    registry = registry.lower()
    if not re.match(r"^0x[0-9a-f]{40}$", registry):
        print(f"Error: Invalid registry address format: {registry}")
        print(f"  Expected: 0x followed by 40 hex characters (lowercase)")
        sys.exit(1)
    return SERVICES_DIR / str(chain_id) / registry


def compute_spki_hash(cert_der_bytes: bytes) -> str:
    """Compute SHA-256 hash of SPKI DER from a certificate."""
    cert = x509.load_der_x509_certificate(cert_der_bytes)
    spki_der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "0x" + hashlib.sha256(spki_der).hexdigest()


def get_cert_info(cert_der_bytes: bytes) -> dict:
    """Extract certificate information."""
    cert = x509.load_der_x509_certificate(cert_der_bytes)
    pub_key = cert.public_key()

    if isinstance(pub_key, rsa.RSAPublicKey):
        algorithm = f"RSA-{pub_key.key_size}"
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        algorithm = f"ECDSA-{pub_key.curve.name}"
    else:
        algorithm = "Unknown"

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_after": cert.not_valid_after_utc.isoformat()[:10],
        "algorithm": algorithm,
    }


def build_sign_message(
    chain_id: str, registry: str, admin: str,
    operation: str, timestamp: int,
) -> str:
    """Build the structured message to sign.

    Format matches tokamak-rollup-metadata-repository pattern:
    structured fields with operation type and Unix timestamp.
    """
    return (
        f"zk-x509-ca-registry\n"
        f"Chain ID: {chain_id}\n"
        f"Registry: {registry.lower()}\n"
        f"Admin: {admin.lower()}\n"
        f"Operation: {operation}\n"
        f"Timestamp: {timestamp}"
    )


def safe_parse_timestamp(sig_data: dict) -> int | None:
    """Safely parse timestamp from signature data, returns None on failure."""
    raw = sig_data.get("timestamp", None)
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


# ─── init ────────────────────────────────────────────────────────────────────


def cmd_init(args):
    """Initialize a new service directory."""
    sdir = get_service_dir(args.chain_id, args.registry)

    if sdir.exists():
        print(f"Error: Service directory already exists: {sdir}")
        sys.exit(1)

    certs_dir = sdir / "certs"
    certs_dir.mkdir(parents=True)

    # Validate admin address format
    admin = args.admin
    if not re.match(r"^0x[0-9a-fA-F]{40}$", admin):
        print(f"Error: Invalid admin address: {admin}")
        sys.exit(1)

    today = date.today().isoformat()
    service = {
        "name": args.name,
        "description": args.description,
        "admin": admin,
        "created_at": today,
        "updated_at": today,
        "cas": {},
    }
    if args.website:
        service["website"] = args.website

    svc_path = sdir / "service.json"
    svc_path.write_text(json.dumps(service, indent=2, ensure_ascii=False) + "\n")

    print(f"✅ Service initialized: {sdir}")
    print(f"   service.json created")
    print(f"   certs/ directory created")
    print(f"\nNext steps:")
    print(f"  1. Add CA certificates:  python admin.py add-ca ...")
    print(f"  2. Sign as admin:        python admin.py sign --operation register ...")
    print(f"  3. Submit PR with title:  [Register] {args.chain_id} {args.registry.lower()} - {args.name}")


# ─── add-ca ──────────────────────────────────────────────────────────────────


def cmd_add_ca(args):
    """Add a CA certificate to the service."""
    sdir = get_service_dir(args.chain_id, args.registry)
    svc_path = sdir / "service.json"
    certs_dir = sdir / "certs"

    if not svc_path.exists():
        print(f"Error: Service not found. Run 'init' first: {sdir}")
        sys.exit(1)

    # Read cert
    cert_path = Path(args.cert)
    if not cert_path.exists():
        print(f"Error: Certificate file not found: {cert_path}")
        sys.exit(1)

    cert_der = cert_path.read_bytes()

    # Validate it's a valid X.509
    try:
        cert_info = get_cert_info(cert_der)
    except ValueError as e:
        print(f"Error: Invalid X.509 DER certificate: {e}")
        sys.exit(1)

    # Check expiry
    cert_obj = x509.load_der_x509_certificate(cert_der)
    now = datetime.now(timezone.utc)
    if cert_obj.not_valid_after_utc < now:
        print(f"Error: Certificate expired on {cert_obj.not_valid_after_utc.date()}")
        sys.exit(1)

    # Compute SPKI hash
    spki_hash = compute_spki_hash(cert_der)
    print(f"Certificate: {cert_info['subject']}")
    print(f"Algorithm:   {cert_info['algorithm']}")
    print(f"SPKI Hash:   {spki_hash}")
    print(f"Expires:     {cert_info['not_after']}")

    # Copy DER file
    certs_dir.mkdir(parents=True, exist_ok=True)
    dest = certs_dir / f"{spki_hash}.der"
    if dest.exists():
        print(f"\n⚠️  Certificate already exists: {dest.name}")
        print(f"   Overwriting...")
    shutil.copy2(cert_path, dest)

    # Update service.json
    service = json.loads(svc_path.read_text())
    ca_entry = {"name": args.name}
    if args.description:
        ca_entry["description"] = args.description

    service["cas"][spki_hash] = ca_entry
    service["updated_at"] = date.today().isoformat()
    svc_path.write_text(json.dumps(service, indent=2, ensure_ascii=False) + "\n")

    print(f"\n✅ CA added: {dest.name}")
    print(f"   service.json updated ({len(service['cas'])} CAs total)")
    print(f"\nNext: sign with --operation add-ca, then submit PR with title:")
    print(f"  [AddCA] {args.chain_id} {args.registry.lower()} - {args.name}")


# ─── remove-ca ───────────────────────────────────────────────────────────────


def cmd_remove_ca(args):
    """Remove a CA certificate from the service."""
    sdir = get_service_dir(args.chain_id, args.registry)
    svc_path = sdir / "service.json"
    certs_dir = sdir / "certs"

    if not svc_path.exists():
        print(f"Error: Service not found: {sdir}")
        sys.exit(1)

    ca_hash = args.hash.lower()
    if not ca_hash.startswith("0x"):
        ca_hash = f"0x{ca_hash}"

    service = json.loads(svc_path.read_text())

    # Find and remove from service.json
    removed_name = None
    for key in list(service.get("cas", {}).keys()):
        if key.lower() == ca_hash:
            removed_name = service["cas"][key].get("name", key)
            del service["cas"][key]
            break

    if removed_name is None:
        print(f"Error: CA hash {ca_hash} not found in service.json")
        sys.exit(1)

    service["updated_at"] = date.today().isoformat()
    svc_path.write_text(json.dumps(service, indent=2, ensure_ascii=False) + "\n")

    # Remove DER file
    der_file = certs_dir / f"{ca_hash}.der"
    if der_file.exists():
        der_file.unlink()
        print(f"✅ Removed: {der_file.name}")
    else:
        print(f"⚠️  DER file not found (already removed?): {der_file.name}")

    print(f"   service.json updated ({len(service['cas'])} CAs remaining)")
    print(f"\nNext: sign with --operation remove-ca, then submit PR with title:")
    print(f"  [RemoveCA] {args.chain_id} {args.registry.lower()} - {removed_name}")


# ─── sign ────────────────────────────────────────────────────────────────────


def cmd_sign(args):
    """Sign to prove admin identity with operation type and timestamp."""
    try:
        from eth_account import Account
        from eth_account.messages import encode_defunct
    except ImportError:
        print("Error: eth-account package required.")
        print("  Install: pip install eth-account")
        sys.exit(1)

    if args.operation not in VALID_OPERATIONS:
        print(f"Error: Invalid operation '{args.operation}'")
        print(f"  Valid operations: {', '.join(VALID_OPERATIONS)}")
        sys.exit(1)

    sdir = get_service_dir(args.chain_id, args.registry)
    svc_path = sdir / "service.json"

    if not svc_path.exists():
        print(f"Error: Service not found: {sdir}")
        sys.exit(1)

    service = json.loads(svc_path.read_text())
    admin_address = service.get("admin", "").lower()

    # Derive signer address from private key
    try:
        account = Account.from_key(args.private_key)
    except (ValueError, binascii.Error) as e:
        print(f"Error: Invalid private key: {e}")
        sys.exit(1)

    signer_address = account.address.lower()

    if signer_address != admin_address:
        print(f"Error: Signer address {signer_address} does not match admin {admin_address}")
        sys.exit(1)

    # Build structured message with timestamp
    timestamp = int(time.time())
    message_text = build_sign_message(
        args.chain_id, args.registry, admin_address,
        args.operation, timestamp,
    )

    # Sign
    message = encode_defunct(text=message_text)
    signed = account.sign_message(message)

    # Save signature with 0x prefix
    sig_hex = signed.signature.hex()
    if not sig_hex.startswith("0x"):
        sig_hex = f"0x{sig_hex}"

    sig_data = {
        "message": message_text,
        "signature": sig_hex,
        "address": signer_address,
        "operation": args.operation,
        "timestamp": timestamp,
        "signed_at": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
    }

    sig_path = sdir / "signature.json"
    sig_path.write_text(json.dumps(sig_data, indent=2) + "\n")

    print(f"✅ Signed as: {signer_address}")
    print(f"   Operation: {args.operation}")
    print(f"   Timestamp: {sig_data['signed_at']}")
    print(f"   Expires:   24 hours from now")
    print(f"   Saved to:  {sig_path}")


# ─── verify ──────────────────────────────────────────────────────────────────


def cmd_verify(args):
    """Verify an admin signature (checks 24h expiry)."""
    try:
        from eth_account import Account
        from eth_account.messages import encode_defunct
    except ImportError:
        print("Error: eth-account package required.")
        print("  Install: pip install eth-account")
        sys.exit(1)

    sdir = get_service_dir(args.chain_id, args.registry)
    sig_path = sdir / "signature.json"
    svc_path = sdir / "service.json"

    if not sig_path.exists():
        print(f"Error: No signature.json found in: {sdir}")
        sys.exit(1)

    if not svc_path.exists():
        print(f"Error: No service.json found in: {sdir}")
        sys.exit(1)

    sig_data = json.loads(sig_path.read_text())
    service = json.loads(svc_path.read_text())

    admin_address = service.get("admin", "").lower()
    claimed_address = sig_data.get("address", "").lower()

    # Check address match
    if claimed_address != admin_address:
        print(f"❌ Signer {claimed_address} != admin {admin_address}")
        sys.exit(1)

    # Validate and coerce timestamp
    sig_timestamp = safe_parse_timestamp(sig_data)
    if sig_timestamp is None:
        print(
            f"Error: Invalid 'timestamp' in signature.json: "
            f"expected integer UNIX timestamp, got {sig_data.get('timestamp')!r}"
        )
        sys.exit(1)

    # Check expiry
    now = int(time.time())
    age = now - sig_timestamp

    if age > SIGNATURE_EXPIRY_SECONDS:
        hours = age // 3600
        print(f"❌ Signature expired: signed {hours}h ago (max 24h)")
        print(f"   Re-sign with: python admin.py sign --operation {sig_data.get('operation', '?')} ...")
        sys.exit(1)

    if sig_timestamp > now + 60:
        print(f"❌ Signature timestamp is in the future")
        sys.exit(1)

    # Recover signer from signature
    message = encode_defunct(text=sig_data["message"])
    signature_hex = sig_data["signature"]
    if not signature_hex.startswith("0x"):
        signature_hex = f"0x{signature_hex}"

    recovered = Account.recover_message(message, signature=signature_hex).lower()

    if recovered != admin_address:
        print(f"❌ Signature invalid: recovered {recovered}, expected {admin_address}")
        sys.exit(1)

    remaining = SIGNATURE_EXPIRY_SECONDS - age
    remaining_h = remaining // 3600
    remaining_m = (remaining % 3600) // 60

    print(f"✅ Signature verified")
    print(f"   Admin:     {admin_address}")
    print(f"   Operation: {sig_data.get('operation', '?')}")
    print(f"   Signed at: {sig_data.get('signed_at', '?')}")
    print(f"   Expires in: {remaining_h}h {remaining_m}m")


# ─── list ────────────────────────────────────────────────────────────────────


def cmd_list(args):
    """List all services or CAs in a service."""
    if args.chain_id and args.registry:
        sdir = get_service_dir(args.chain_id, args.registry)
        svc_path = sdir / "service.json"
        if not svc_path.exists():
            print(f"Service not found: {sdir}")
            sys.exit(1)

        service = json.loads(svc_path.read_text())
        print(f"Service: {service['name']}")
        print(f"Admin:   {service['admin']}")
        print(f"Created: {service.get('created_at', '?')}")
        print(f"Updated: {service.get('updated_at', '?')}")
        print(f"\nCAs ({len(service['cas'])}):")
        for h, info in service["cas"].items():
            der_exists = "✅" if (sdir / "certs" / f"{h}.der").exists() else "❌"
            print(f"  {der_exists} {h}")
            print(f"     Name: {info.get('name', '?')}")
            if info.get("description"):
                print(f"     Desc: {info['description']}")

        # Show signature status
        sig_path = sdir / "signature.json"
        if sig_path.exists():
            sig_data = json.loads(sig_path.read_text())
            ts = safe_parse_timestamp(sig_data)
            if ts is not None:
                age = int(time.time()) - ts
                expired = age > SIGNATURE_EXPIRY_SECONDS
                status = "❌ expired" if expired else "✅ valid"
            else:
                status = "⚠️ invalid timestamp"
            print(f"\nSignature: {status} (op: {sig_data.get('operation', '?')})")
        else:
            print(f"\nSignature: ⚠️  not signed")
    else:
        if not SERVICES_DIR.exists():
            print("No services registered yet.")
            return

        count = 0
        for chain_dir in sorted(SERVICES_DIR.iterdir()):
            if not chain_dir.is_dir():
                continue
            for reg_dir in sorted(chain_dir.iterdir()):
                svc_path = reg_dir / "service.json"
                if svc_path.exists():
                    service = json.loads(svc_path.read_text())
                    cas_count = len(service.get("cas", {}))
                    print(f"  {chain_dir.name}/{reg_dir.name}")
                    print(f"    Name:  {service.get('name', '?')}")
                    print(f"    Admin: {service.get('admin', '?')}")
                    print(f"    CAs:   {cas_count}")
                    print()
                    count += 1

        if count == 0:
            print("No services registered yet.")
        else:
            print(f"Total: {count} services")


# ─── main ────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="Admin CLI for zk-x509-ca-registry",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Command")

    p_init = subparsers.add_parser("init", help="Initialize a new service")
    p_init.add_argument("--chain-id", required=True, help="Chain ID (e.g., 11155111)")
    p_init.add_argument("--registry", required=True, help="Registry contract address (0x...)")
    p_init.add_argument("--name", required=True, help="Service display name")
    p_init.add_argument("--description", required=True, help="Service description")
    p_init.add_argument("--admin", required=True, help="Admin Ethereum address (0x...)")
    p_init.add_argument("--website", help="Service website URL")

    p_add = subparsers.add_parser("add-ca", help="Add a CA certificate")
    p_add.add_argument("--chain-id", required=True, help="Chain ID")
    p_add.add_argument("--registry", required=True, help="Registry contract address")
    p_add.add_argument("--cert", required=True, help="Path to CA certificate (DER format)")
    p_add.add_argument("--name", required=True, help="CA display name")
    p_add.add_argument("--description", help="CA description")

    p_rm = subparsers.add_parser("remove-ca", help="Remove a CA certificate")
    p_rm.add_argument("--chain-id", required=True, help="Chain ID")
    p_rm.add_argument("--registry", required=True, help="Registry contract address")
    p_rm.add_argument("--hash", required=True, help="CA SPKI hash to remove (0x...)")

    p_sign = subparsers.add_parser("sign", help="Sign to prove admin identity")
    p_sign.add_argument("--chain-id", required=True, help="Chain ID")
    p_sign.add_argument("--registry", required=True, help="Registry contract address")
    p_sign.add_argument("--private-key", required=True, help="Admin private key (0x...)")
    p_sign.add_argument(
        "--operation", required=True, choices=VALID_OPERATIONS,
        help="Operation type: register, add-ca, remove-ca, update",
    )

    p_verify = subparsers.add_parser("verify", help="Verify admin signature")
    p_verify.add_argument("--chain-id", required=True, help="Chain ID")
    p_verify.add_argument("--registry", required=True, help="Registry contract address")

    p_list = subparsers.add_parser("list", help="List services or CAs")
    p_list.add_argument("--chain-id", help="Chain ID (omit to list all)")
    p_list.add_argument("--registry", help="Registry contract address")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        "init": cmd_init,
        "add-ca": cmd_add_ca,
        "remove-ca": cmd_remove_ca,
        "sign": cmd_sign,
        "verify": cmd_verify,
        "list": cmd_list,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
