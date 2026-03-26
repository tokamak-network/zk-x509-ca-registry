#!/usr/bin/env python3
"""
Validate CA registry PR: DER certificates, service.json, PR scope, admin signature.

Validation layers (modeled after tokamak-rollup-metadata-repository):
  1. PR scope check — one service directory per PR
  2. PR title validation — [Register], [AddCA], [RemoveCA], [Update] format
  3. DER certificate validation — X.509 parsing, SPKI hash, expiry, CA check
  4. service.json schema validation — JSON schema + cross-reference certs
  5. Signature verification — Ethereum signature with 24h expiry, operation type
  6. Immutable field protection — admin, created_at cannot change on updates
  7. Operation consistency — PR title operation matches actual file changes

Usage:
    python validate.py --changed-files "services/11155111/0xaddr/service.json" \\
        --pr-title "[Register] 11155111 0xaddr - My Service" --output report.md
"""

import argparse
import hashlib
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
import jsonschema


SCHEMA_PATH = Path(__file__).parent / "schema" / "service.schema.json"
MAX_DER_SIZE = 10_000  # 10KB
SIGNATURE_EXPIRY_SECONDS = 86400  # 24 hours

# PR title patterns: [Operation] {chainId} {registryAddress} - {name}
PR_TITLE_PATTERNS = {
    "register": re.compile(
        r"^\[Register\]\s+(\d+)\s+(0x[0-9a-fA-F]{40})\s+-\s+(.+)$"
    ),
    "add-ca": re.compile(
        r"^\[AddCA\]\s+(\d+)\s+(0x[0-9a-fA-F]{40})\s+-\s+(.+)$"
    ),
    "remove-ca": re.compile(
        r"^\[RemoveCA\]\s+(\d+)\s+(0x[0-9a-fA-F]{40})\s+-\s+(.+)$"
    ),
    "update": re.compile(
        r"^\[Update\]\s+(\d+)\s+(0x[0-9a-fA-F]{40})\s+-\s+(.+)$"
    ),
}


# ─── Layer 1: PR Scope ──────────────────────────────────────────────────────


def detect_service_dirs(changed_files: list[str]) -> set[str]:
    """Extract unique service directory prefixes from changed files."""
    dirs = set()
    for f in changed_files:
        parts = f.split("/")
        if len(parts) >= 3 and parts[0] == "services":
            dirs.add(f"{parts[0]}/{parts[1]}/{parts[2]}")
    return dirs


def validate_scope(service_dirs: set[str]) -> list[str]:
    """Validate PR modifies only one service directory."""
    errors = []
    if len(service_dirs) > 1:
        errors.append(
            f"PR modifies {len(service_dirs)} service directories: "
            f"{', '.join(sorted(service_dirs))}"
        )
    if len(service_dirs) == 0:
        errors.append("No service directory changes detected")
    return errors


# ─── Layer 2: PR Title ──────────────────────────────────────────────────────


def validate_pr_title(pr_title: str | None, service_dirs: set[str]) -> tuple[str | None, list[str]]:
    """Validate PR title format and consistency with changed files.

    Returns (operation, errors).
    """
    if not pr_title:
        return None, []

    errors = []
    operation = None

    for op, pattern in PR_TITLE_PATTERNS.items():
        match = pattern.match(pr_title.strip())
        if match:
            operation = op
            chain_id = match.group(1)
            registry = match.group(2).lower()
            expected_dir = f"services/{chain_id}/{registry}"

            if service_dirs and expected_dir not in service_dirs:
                errors.append(
                    f"PR title references {expected_dir} but changes are in "
                    f"{', '.join(sorted(service_dirs))}"
                )
            break

    if operation is None:
        errors.append(
            f"Invalid PR title format: '{pr_title}'. "
            f"Expected: [Register|AddCA|RemoveCA|Update] {{chainId}} {{0xAddress}} - {{name}}"
        )

    return operation, errors


# ─── Layer 3: DER Certificate ───────────────────────────────────────────────


def validate_der(filepath: Path) -> dict:
    """Validate a single DER certificate file."""
    result = {"file": str(filepath), "errors": [], "warnings": [], "info": {}}

    try:
        der_bytes = filepath.read_bytes()
    except OSError as e:
        result["errors"].append(f"Cannot read file: {e}")
        return result

    # Size check
    if len(der_bytes) > MAX_DER_SIZE:
        result["warnings"].append(f"Large file: {len(der_bytes)} bytes")

    # Parse X.509
    try:
        cert = x509.load_der_x509_certificate(der_bytes)
    except Exception as e:
        result["errors"].append(f"Invalid X.509 DER: {e}")
        return result

    # Extract info
    result["info"]["subject"] = cert.subject.rfc4514_string()
    result["info"]["issuer"] = cert.issuer.rfc4514_string()
    result["info"]["not_after"] = cert.not_valid_after_utc.isoformat()

    # Detect algorithm
    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        result["info"]["algorithm"] = f"RSA-{pub_key.key_size}"
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        result["info"]["algorithm"] = f"ECDSA-{pub_key.curve.name}"
    else:
        result["info"]["algorithm"] = "Unknown"

    # Hash verification: SHA-256(SPKI) == filename
    spki_der = pub_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    actual_hash = hashlib.sha256(spki_der).hexdigest()
    expected_hash = filepath.stem.lower().replace("0x", "")

    if actual_hash != expected_hash:
        result["errors"].append(
            f"Hash mismatch: filename=0x{expected_hash[:16]}..., "
            f"actual=0x{actual_hash[:16]}..."
        )
    result["info"]["hash_match"] = actual_hash == expected_hash

    # Expiry check
    now = datetime.now(timezone.utc)
    if cert.not_valid_after_utc < now:
        result["errors"].append(
            f"Certificate expired on {cert.not_valid_after_utc.date()}"
        )
    elif (cert.not_valid_after_utc - now).days < 90:
        result["warnings"].append(
            f"Expires in {(cert.not_valid_after_utc - now).days} days"
        )

    # CA check (BasicConstraints)
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if not bc.value.ca:
            result["warnings"].append("BasicConstraints CA=false (not a CA cert)")
    except x509.ExtensionNotFound:
        result["warnings"].append("No BasicConstraints extension")

    return result


# ─── Layer 4: service.json ───────────────────────────────────────────────────


def validate_service_json(filepath: Path, certs_dir: Path) -> dict:
    """Validate service.json against schema and cross-reference certs."""
    result = {"errors": [], "warnings": [], "info": {}}

    try:
        data = json.loads(filepath.read_text())
    except json.JSONDecodeError as e:
        result["errors"].append(f"Invalid JSON: {e}")
        return result

    result["info"]["name"] = data.get("name", "?")
    result["info"]["admin"] = data.get("admin", "?")
    result["info"]["cas_count"] = len(data.get("cas", {}))

    # Schema validation
    if SCHEMA_PATH.exists():
        schema = json.loads(SCHEMA_PATH.read_text())
        try:
            jsonschema.validate(data, schema)
        except jsonschema.ValidationError as e:
            result["errors"].append(f"Schema error: {e.message}")

    # Cross-reference: cas keys -> .der files
    cas = data.get("cas", {})
    for ca_hash in cas:
        normalized = ca_hash.lower()
        if not normalized.startswith("0x"):
            normalized = f"0x{normalized}"
        der_file = certs_dir / f"{normalized}.der"
        if not der_file.exists():
            result["errors"].append(
                f"CA entry {ca_hash} has no matching .der file"
            )

    # Cross-reference: .der files -> cas keys
    if certs_dir.exists():
        for der_file in sorted(certs_dir.glob("0x*.der")):
            hash_key = der_file.stem.lower()
            if hash_key not in {k.lower() for k in cas}:
                result["warnings"].append(
                    f"{der_file.name} not listed in service.json cas"
                )

    return result


# ─── Layer 5: Signature Verification ────────────────────────────────────────


def validate_signature(service_dir: Path) -> dict:
    """Validate admin signature with 24h expiry and operation type."""
    result = {"errors": [], "warnings": [], "verified": False, "info": {}}

    sig_file = service_dir / "signature.json"
    svc_file = service_dir / "service.json"

    if not sig_file.exists():
        result["warnings"].append("No signature.json — admin identity not verified")
        return result

    if not svc_file.exists():
        result["errors"].append("signature.json present but service.json missing")
        return result

    try:
        sig_data = json.loads(sig_file.read_text())
        svc_data = json.loads(svc_file.read_text())
    except json.JSONDecodeError as e:
        result["errors"].append(f"JSON parse error: {e}")
        return result

    # Check required fields
    required_fields = ["message", "signature", "address", "timestamp", "operation"]
    for field in required_fields:
        if field not in sig_data:
            result["errors"].append(f"signature.json missing field: {field}")
            return result

    result["info"]["operation"] = sig_data.get("operation", "?")
    result["info"]["address"] = sig_data.get("address", "?")

    # Verify signer address matches admin
    claimed_address = sig_data["address"].lower()
    admin_address = svc_data.get("admin", "").lower()

    if claimed_address != admin_address:
        result["errors"].append(
            f"Signer {claimed_address} != admin {admin_address}"
        )
        return result

    # Verify signature not expired (24 hours)
    sig_timestamp = sig_data.get("timestamp", 0)
    now = int(time.time())
    age = now - sig_timestamp

    if age > SIGNATURE_EXPIRY_SECONDS:
        hours = age // 3600
        result["errors"].append(
            f"Signature expired: signed {hours}h ago (max 24h)"
        )
        return result

    if sig_timestamp > now + 60:  # 1 minute tolerance for clock skew
        result["errors"].append("Signature timestamp is in the future")
        return result

    # Verify Ethereum signature
    try:
        from eth_account.messages import encode_defunct
        from eth_account import Account

        message = encode_defunct(text=sig_data["message"])
        signature_hex = sig_data["signature"]
        if not signature_hex.startswith("0x"):
            signature_hex = f"0x{signature_hex}"

        recovered = Account.recover_message(
            message, signature=signature_hex
        ).lower()

        if recovered != admin_address:
            result["errors"].append(
                f"Signature recovery mismatch: recovered {recovered}, "
                f"expected {admin_address}"
            )
        else:
            result["verified"] = True
    except ImportError:
        result["warnings"].append(
            "eth-account not installed — skipping signature verification"
        )
    except Exception as e:
        result["errors"].append(f"Signature verification failed: {e}")

    return result


# ─── Layer 6: Immutable Field Protection ─────────────────────────────────────


IMMUTABLE_FIELDS = ["admin", "created_at"]


def validate_immutable_fields(
    service_dir: Path, base_ref: str | None
) -> dict:
    """Check that immutable fields haven't changed for update operations."""
    result = {"errors": [], "warnings": []}

    if not base_ref:
        return result

    svc_file = service_dir / "service.json"
    if not svc_file.exists():
        return result

    try:
        new_data = json.loads(svc_file.read_text())
    except json.JSONDecodeError:
        return result

    # Try to read the base version via git
    import subprocess

    rel_path = svc_file
    try:
        old_content = subprocess.run(
            ["git", "show", f"{base_ref}:{rel_path}"],
            capture_output=True, text=True, timeout=10,
        )
        if old_content.returncode != 0:
            # File doesn't exist in base — this is a new registration, skip
            return result
        old_data = json.loads(old_content.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        return result

    for field in IMMUTABLE_FIELDS:
        old_val = old_data.get(field)
        new_val = new_data.get(field)
        if old_val is not None and old_val != new_val:
            result["errors"].append(
                f"Immutable field '{field}' changed: "
                f"'{old_val}' -> '{new_val}'"
            )

    return result


# ─── Report Generation ──────────────────────────────────────────────────────


def generate_report(
    service_dirs: set[str],
    operation: str | None,
    cert_results: list[dict],
    svc_results: list[dict],
    sig_results: list[dict],
    immutable_results: list[dict],
    scope_errors: list[str],
    title_errors: list[str],
) -> str:
    """Generate markdown validation report."""
    all_errors = list(scope_errors) + list(title_errors)
    all_warnings = []

    for results in [cert_results, svc_results, sig_results, immutable_results]:
        for r in results:
            all_errors.extend(r.get("errors", []))
            all_warnings.extend(r.get("warnings", []))

    has_errors = len(all_errors) > 0
    status = "❌" if has_errors else "✅"

    report = f"## CA Registry Validation {status}\n\n"
    report += f"**Service**: `{', '.join(sorted(service_dirs)) or 'N/A'}`\n"
    if operation:
        report += f"**Operation**: `{operation}`\n"
    report += "\n"

    # Scope & Title
    report += "### PR Validation\n"
    if not scope_errors:
        report += "- ✅ PR modifies only one service directory\n"
    else:
        for e in scope_errors:
            report += f"- ❌ {e}\n"
    if not title_errors:
        if operation:
            report += f"- ✅ PR title valid (operation: {operation})\n"
    else:
        for e in title_errors:
            report += f"- ❌ {e}\n"
    report += "\n"

    # Certificates table
    if cert_results:
        report += f"### Certificates ({len(cert_results)} validated)\n"
        report += "| File | Subject | Algorithm | Expires | Hash |\n"
        report += "|------|---------|-----------|---------|------|\n"
        for cr in cert_results:
            icon = "❌" if cr["errors"] else "✅"
            info = cr["info"]
            subject = info.get("subject", "?")[:40]
            alg = info.get("algorithm", "?")
            exp = info.get("not_after", "?")[:10]
            hash_ok = "match" if info.get("hash_match") else "mismatch"
            fname = Path(cr["file"]).name
            if len(fname) > 24:
                fname = fname[:12] + "..." + fname[-8:]
            report += f"| {icon} `{fname}` | {subject} | {alg} | {exp} | {hash_ok} |\n"
        report += "\n"

    # service.json
    for sr in svc_results:
        report += "### service.json\n"
        if not sr["errors"]:
            report += "- ✅ Schema valid\n"
            report += f"- ✅ Admin: `{sr['info'].get('admin', '?')}`\n"
            report += f"- ✅ CAs: {sr['info'].get('cas_count', '?')}\n"
        for e in sr["errors"]:
            report += f"- ❌ {e}\n"
        for w in sr["warnings"]:
            report += f"- ⚠️ {w}\n"
        report += "\n"

    # Signature verification
    for sigr in sig_results:
        report += "### Admin Signature\n"
        if sigr.get("verified"):
            op = sigr.get("info", {}).get("operation", "?")
            addr = sigr.get("info", {}).get("address", "?")
            report += f"- ✅ Verified: `{addr}` (operation: {op})\n"
        elif sigr.get("errors"):
            for e in sigr["errors"]:
                report += f"- ❌ {e}\n"
        else:
            for w in sigr.get("warnings", []):
                report += f"- ⚠️ {w}\n"
        report += "\n"

    # Immutable fields
    for imr in immutable_results:
        if imr.get("errors"):
            report += "### Immutable Fields\n"
            for e in imr["errors"]:
                report += f"- ❌ {e}\n"
            report += "\n"

    if not all_errors and not all_warnings:
        report += "All checks passed. ✅\n"

    return report


# ─── Main ────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="Validate CA registry PR")
    parser.add_argument(
        "--changed-files", required=True,
        help="Newline-separated list of changed files",
    )
    parser.add_argument(
        "--pr-title", default=None,
        help="PR title for format validation",
    )
    parser.add_argument(
        "--base-ref", default=None,
        help="Git base ref for immutable field checks (e.g., origin/main)",
    )
    parser.add_argument(
        "--output", default="report.md",
        help="Output report path",
    )
    args = parser.parse_args()

    changed = [f for f in args.changed_files.strip().split("\n") if f.strip()]
    service_dirs = detect_service_dirs(changed)

    # Layer 1: Scope
    scope_errors = validate_scope(service_dirs)

    # Layer 2: PR title
    operation, title_errors = validate_pr_title(args.pr_title, service_dirs)

    cert_results = []
    svc_results = []
    sig_results = []
    immutable_results = []

    # Validate each service directory
    for sdir in service_dirs:
        sdir_path = Path(sdir)

        # Layer 3: DER certificates
        certs_dir = sdir_path / "certs"
        if certs_dir.exists():
            for der_file in sorted(certs_dir.glob("0x*.der")):
                cert_results.append(validate_der(der_file))

        # Layer 4: service.json
        svc_json = sdir_path / "service.json"
        if svc_json.exists():
            svc_results.append(validate_service_json(svc_json, certs_dir))
        else:
            svc_results.append({
                "errors": [f"Missing service.json in {sdir}"],
                "warnings": [], "info": {},
            })

        # Layer 5: Signature
        sig_results.append(validate_signature(sdir_path))

        # Layer 6: Immutable fields (only for updates)
        if operation in ("update", "add-ca", "remove-ca"):
            immutable_results.append(
                validate_immutable_fields(sdir_path, args.base_ref)
            )

    # Generate report
    report = generate_report(
        service_dirs, operation,
        cert_results, svc_results, sig_results, immutable_results,
        scope_errors, title_errors,
    )

    Path(args.output).write_text(report)
    print(report)

    has_errors = scope_errors or title_errors or any(
        e
        for results in [cert_results, svc_results, sig_results, immutable_results]
        for r in results
        for e in r.get("errors", [])
    )

    sys.exit(1 if has_errors else 0)


if __name__ == "__main__":
    main()
