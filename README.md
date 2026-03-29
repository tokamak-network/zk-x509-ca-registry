# zk-x509-ca-registry

CA certificate registry for the zk-X509 platform.

Service administrators manage DER-encoded CA certificates and metadata for their on-chain registries. The zk-X509 prover and frontend fetch CA certificates and service information from this repository.

## Structure

```
services/
  {chainId}/                          # Chain ID (e.g., 11155111 = Sepolia)
    {registryAddress}/                # Registry contract address (lowercase 0x)
      service.json                    # Service metadata + CA guides
      signature.json                  # Admin signature (24h validity)
      certs/
        0x{sha256_spki_hash}.der      # CA certificate (DER format)
```

- **Filename convention**: DER filename = `0x` + `SHA-256(SPKI DER)` lowercase hex
- **On-chain matching**: Filename hash matches on-chain `getCaLeaves()` values
- **Lowercase convention**: All hex values (addresses, hashes) use lowercase

## How It Works

```
On-chain contract                    This repository
  getCaLeaves() → [hash1, hash2]     services/{chainId}/{addr}/certs/
                                       0x{hash1}.der  ← actual certificate
                                       0x{hash2}.der

Prover: on-chain hash → deterministic URL → download DER → verify SHA-256(SPKI)
Frontend: service.json → display service info + CA issuance guides
```

Security: This repository is **untrusted**. The prover always verifies that `SHA-256(SPKI)` of the downloaded certificate matches the on-chain hash.

## service.json Format

```json
{
  "name": "DAO Voting Registry",
  "description": "One person, one vote identity verification for DAO governance",
  "admin": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
  "website": "https://mydao.org",
  "created_at": "2024-01-15",
  "updated_at": "2024-01-15",
  "cas": {
    "0x28a2f0e0...abcd1234": {
      "name": "yessignCA Class 3",
      "description": "Korean banking certificate CA issued by KFTC"
    }
  }
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Service name (max 100 chars) |
| `description` | Yes | Service description (max 500 chars) |
| `admin` | Yes | Admin Ethereum address (`0x` + 40 hex) |
| `website` | No | Service website URL |
| `created_at` | Yes | Creation date (YYYY-MM-DD) — immutable field |
| `updated_at` | Yes | Last update date (YYYY-MM-DD) |
| `cas` | Yes | CA entries (key: `0x` + SHA-256(SPKI) 64 hex) |

**Immutable fields**: `admin` and `created_at` cannot be changed after registration.

## Admin CLI

Use the admin CLI tool to register services and manage CA certificates.

### Installation

```bash
pip install -r scripts/requirements.txt
```

### Register a New Service

```bash
python scripts/admin.py init \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 \
  --name "My DAO Voting" \
  --description "Identity verification service for DAO governance" \
  --admin 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
  --website "https://mydao.org"
```

### Add a CA Certificate

```bash
python scripts/admin.py add-ca \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 \
  --cert /path/to/ca-certificate.der \
  --name "yessignCA Class 3" \
  --description "Korean banking CA issued by KFTC"
```

This command automatically:
1. Parses the DER certificate as X.509 (checks expiry)
2. Computes `SHA-256(SPKI)` hash for the filename
3. Copies to the `certs/` directory
4. Adds entry to `service.json` `cas`

### Remove a CA Certificate

```bash
python scripts/admin.py remove-ca \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 \
  --hash 0x28a2f0e0abcd1234...
```

### List Services

```bash
# List all services
python scripts/admin.py list

# List CAs in a specific service + signature status
python scripts/admin.py list \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512
```

## Admin Signature Verification

Admin identity is verified via Ethereum address signatures when submitting PRs.

### Signature Design

Follows the same pattern as `tokamak-rollup-metadata-repository`:
- **Structured message**: includes chain ID, registry, admin, operation, timestamp
- **24-hour expiry**: PR must be merged within 24 hours of signing
- **Operation type**: register, add-ca, remove-ca, update
- **Replay prevention**: Unix timestamp prevents signature reuse

### Create Signature

```bash
python scripts/admin.py sign \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 \
  --private-key $ADMIN_PRIVATE_KEY \
  --operation register    # register | add-ca | remove-ca | update
```

Generated `signature.json`:

```json
{
  "message": "zk-x509-ca-registry\nChain ID: 11155111\nRegistry: 0xe7f1...\nAdmin: 0xf39f...\nOperation: register\nTimestamp: 1711425600",
  "signature": "0x...",
  "address": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
  "operation": "register",
  "timestamp": 1711425600,
  "signed_at": "2024-01-15T12:00:00+00:00"
}
```

### Verify Signature

```bash
python scripts/admin.py verify \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512
```

Verification checks:
1. Recovered address from signature == `admin` address in service.json
2. Signed message matches expected structured format
3. Signature is within 24-hour validity window
4. Rejects future timestamps

## Submitting a PR

### PR Title Format

| Operation | PR Title Format | Example |
|-----------|----------------|---------|
| Register service | `[Register] {chainId} {0xAddr} - {name}` | `[Register] 11155111 0xe7f1...0512 - My DAO` |
| Add CA | `[AddCA] {chainId} {0xAddr} - {caName}` | `[AddCA] 11155111 0xe7f1...0512 - yessignCA` |
| Remove CA | `[RemoveCA] {chainId} {0xAddr} - {caName}` | `[RemoveCA] 11155111 0xe7f1...0512 - Old CA` |
| Update info | `[Update] {chainId} {0xAddr} - {name}` | `[Update] 11155111 0xe7f1...0512 - My DAO` |

### 1. Register a New Service

**Prerequisite**: Deploy the registry contract on-chain and register CAs via `addCA()`

```bash
# 1. Fork & Clone
git clone https://github.com/YOUR_USERNAME/zk-x509-ca-registry.git
cd zk-x509-ca-registry

# 2. Install dependencies
pip install -r scripts/requirements.txt

# 3. Create branch
git checkout -b register/my-dao-voting

# 4. Initialize service
python scripts/admin.py init \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 \
  --name "My DAO Voting" \
  --description "Identity verification for DAO governance" \
  --admin 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

# 5. Add CA certificates (for each CA registered on-chain)
python scripts/admin.py add-ca \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 \
  --cert ~/certs/yessign-ca.der \
  --name "yessignCA Class 3" \
  --description "Korean banking CA"

# 6. Sign as admin (valid for 24 hours — sign just before PR submission)
python scripts/admin.py sign \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 \
  --private-key $ADMIN_PRIVATE_KEY \
  --operation register

# 7. Commit & push
git add services/
git commit -m "Register service: My DAO Voting (Sepolia)"
git push origin register/my-dao-voting

# 8. Create PR on GitHub
#    Title: [Register] 11155111 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 - My DAO Voting
```

### 2. Add a CA

```bash
git checkout -b add-ca/yessign-class3

python scripts/admin.py add-ca \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 \
  --cert ~/certs/new-ca.der \
  --name "New CA Name"

python scripts/admin.py sign \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 \
  --private-key $ADMIN_PRIVATE_KEY \
  --operation add-ca

git add services/
git commit -m "Add CA: New CA Name"
git push origin add-ca/yessign-class3
# PR title: [AddCA] 11155111 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 - New CA Name
```

### 3. Remove a CA

```bash
git checkout -b remove-ca/old-ca

python scripts/admin.py remove-ca \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 \
  --hash 0x28a2f0e0...

python scripts/admin.py sign \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 \
  --private-key $ADMIN_PRIVATE_KEY \
  --operation remove-ca

git add services/
git commit -m "Remove CA: Old CA Name"
git push origin remove-ca/old-ca
# PR title: [RemoveCA] 11155111 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 - Old CA Name
```

### 4. Update Service Info

```bash
git checkout -b update/description
# Edit service.json (name, description, website, etc.)
# Note: admin and created_at are immutable and cannot be changed

python scripts/admin.py sign \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 \
  --private-key $ADMIN_PRIVATE_KEY \
  --operation update

git add services/
git commit -m "Update service info"
git push origin update/description
# PR title: [Update] 11155111 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 - My DAO Voting
```

## CI Validation (7-Layer)

Runs automatically on PRs that modify files under `services/`:

| Layer | Check | Description |
|-------|-------|-------------|
| 1 | **PR Scope** | Only one service directory modified per PR |
| 2 | **PR Title** | `[Register\|AddCA\|RemoveCA\|Update] {chainId} {addr} - {name}` format |
| 3 | **DER Certificate** | X.509 parsing, SPKI hash match, expiry, CA flag |
| 4 | **service.json** | JSON schema validation, cas ↔ certs cross-reference |
| 5 | **Signature** | Ethereum signature recovery, admin match, 24h expiry |
| 6 | **Immutable Fields** | Blocks changes to admin, created_at on updates |
| 7 | **Operation Consistency** | PR title operation matches actual file changes |

**On validation pass**: PR is automatically squash-merged.

## Security Model

| Threat | Mitigation |
|--------|-----------|
| Repository serves wrong certificate | Prover verifies `SHA-256(SPKI) == on-chain hash` |
| Repository unavailable | Local cache serves previously verified certificates |
| Man-in-the-middle attack | Hash verification detects any modification |
| Admin impersonation PR | Ethereum address signature verification (24h expiry) |
| Signature replay attack | Unix timestamp + operation type prevents reuse |
| Immutable field tampering | CI compares against base branch to detect changes |
| Multi-service modification | PR scope check (only 1 directory allowed) |
| Malicious DER file | Rejected if >10KB + X.509 parsing validation |
| Expired certificate registration | Expiry date validation (warning at <90 days) |

## License

MIT
