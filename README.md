# zk-x509-ca-registry

zk-X509 플랫폼에서 사용하는 CA 인증서 레지스트리입니다.

각 서비스 관리자(admin)가 온체인 레지스트리에 등록한 CA 인증서의 원본(DER)과 메타데이터를 관리합니다. zk-X509 프로버와 프론트엔드는 이 저장소에서 CA 인증서와 서비스 정보를 가져옵니다.

## 구조

```
services/
  {chainId}/                          # 체인 ID (예: 11155111 = Sepolia)
    {registryAddress}/                # 레지스트리 컨트랙트 주소 (소문자 0x)
      service.json                    # 서비스 메타데이터 + CA 안내
      signature.json                  # 관리자 서명 (24시간 유효)
      certs/
        0x{sha256_spki_hash}.der      # CA 인증서 (DER 형식)
```

- **파일명 규칙**: DER 파일명 = `0x` + `SHA-256(SPKI DER)` 소문자 hex
- **온체인 매칭**: 파일명의 해시가 온체인 `getCaLeaves()`의 값과 동일
- **소문자 통일**: 모든 hex 값(주소, 해시)은 소문자 사용

## 동작 원리

```
온체인 컨트랙트                      이 저장소
  getCaLeaves() → [hash1, hash2]     services/{chainId}/{addr}/certs/
                                       0x{hash1}.der  ← 실제 인증서
                                       0x{hash2}.der

프로버: 온체인 해시 → URL 결정적 → DER 다운로드 → SHA-256(SPKI) 검증
프론트: service.json → 서비스 정보 + CA 발급 안내 표시
```

보안: 이 저장소는 **untrusted**입니다. 다운로드한 인증서의 `SHA-256(SPKI)`가 온체인 해시와 일치하는지 반드시 검증합니다.

## service.json 형식

```json
{
  "name": "DAO Voting Registry",
  "description": "DAO 거버넌스를 위한 1인 1표 신원 인증",
  "admin": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
  "website": "https://mydao.org",
  "created_at": "2024-01-15",
  "updated_at": "2024-01-15",
  "cas": {
    "0x28a2f0e0...abcd1234": {
      "name": "yessignCA Class 3",
      "description": "한국 금융결제원 발급 은행 인증서 CA",
      "issue_url": "https://www.yessign.or.kr",
      "instructions": "은행 지점을 방문하여 공동인증서를 발급받으세요."
    }
  }
}
```

| 필드 | 필수 | 설명 |
|------|------|------|
| `name` | O | 서비스 이름 (최대 100자) |
| `description` | O | 서비스 설명 (최대 500자) |
| `admin` | O | 관리자 Ethereum 주소 (`0x` + 40 hex) |
| `website` | X | 서비스 웹사이트 URL |
| `created_at` | O | 생성일 (YYYY-MM-DD) — 불변 필드 |
| `updated_at` | O | 최종 수정일 (YYYY-MM-DD) |
| `cas` | O | CA 목록 (키: `0x` + SHA-256(SPKI) 64 hex) |

**불변 필드**: `admin`, `created_at`은 등록 후 변경할 수 없습니다.

## Admin CLI

관리자 도구를 사용하여 서비스를 등록하고 CA를 관리할 수 있습니다.

### 설치

```bash
pip install -r scripts/requirements.txt
```

### 새 서비스 등록

```bash
python scripts/admin.py init \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 \
  --name "My DAO Voting" \
  --description "DAO 거버넌스를 위한 신원 인증 서비스" \
  --admin 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
  --website "https://mydao.org"
```

### CA 인증서 추가

```bash
python scripts/admin.py add-ca \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 \
  --cert /path/to/ca-certificate.der \
  --name "yessignCA Class 3" \
  --description "한국 금융결제원 발급 CA" \
  --issue-url "https://www.yessign.or.kr" \
  --instructions "은행 지점을 방문하여 공동인증서를 발급받으세요."
```

이 명령은 자동으로:
1. DER 인증서를 X.509로 파싱 (만료 확인)
2. `SHA-256(SPKI)` 해시를 계산하여 파일명 생성
3. `certs/` 디렉토리에 복사
4. `service.json`의 `cas`에 항목 추가

### CA 인증서 제거

```bash
python scripts/admin.py remove-ca \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 \
  --hash 0x28a2f0e0abcd1234...
```

### 서비스 목록 조회

```bash
# 전체 서비스 목록
python scripts/admin.py list

# 특정 서비스의 CA 목록 + 서명 상태
python scripts/admin.py list \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512
```

## 관리자 서명 검증

PR 제출 시 관리자 신원을 Ethereum 주소 서명으로 검증합니다.

### 서명 구조

`tokamak-rollup-metadata-repository`와 동일한 패턴을 따릅니다:
- **구조화된 메시지**: chain ID, registry, admin, operation, timestamp 포함
- **24시간 만료**: 서명 후 24시간 내에 PR이 머지되어야 함
- **Operation 타입**: register, add-ca, remove-ca, update
- **리플레이 방지**: Unix timestamp로 동일 서명 재사용 방지

### 서명 생성

```bash
python scripts/admin.py sign \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 \
  --private-key $ADMIN_PRIVATE_KEY \
  --operation register    # register | add-ca | remove-ca | update
```

생성되는 `signature.json`:

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

### 서명 검증

```bash
python scripts/admin.py verify \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512
```

검증 항목:
1. 서명에서 복원된 주소 == service.json의 `admin` 주소
2. 서명 메시지 형식 일치
3. 서명 후 24시간 이내인지 확인
4. 미래 타임스탬프 거부

## PR 제출 방법

### PR 제목 형식

| Operation | PR 제목 형식 | 예시 |
|-----------|-------------|------|
| 서비스 등록 | `[Register] {chainId} {0xAddr} - {name}` | `[Register] 11155111 0xe7f1...0512 - My DAO` |
| CA 추가 | `[AddCA] {chainId} {0xAddr} - {caName}` | `[AddCA] 11155111 0xe7f1...0512 - yessignCA` |
| CA 제거 | `[RemoveCA] {chainId} {0xAddr} - {caName}` | `[RemoveCA] 11155111 0xe7f1...0512 - Old CA` |
| 정보 수정 | `[Update] {chainId} {0xAddr} - {name}` | `[Update] 11155111 0xe7f1...0512 - My DAO` |

### 1. 새 서비스 등록

**사전 조건**: 온체인 레지스트리 컨트랙트를 배포하고 `addCA()`로 CA를 등록한 상태

```bash
# 1. 저장소 Fork & Clone
git clone https://github.com/YOUR_USERNAME/zk-x509-ca-registry.git
cd zk-x509-ca-registry

# 2. 의존성 설치
pip install -r scripts/requirements.txt

# 3. 브랜치 생성
git checkout -b register/my-dao-voting

# 4. 서비스 초기화
python scripts/admin.py init \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 \
  --name "My DAO Voting" \
  --description "DAO 거버넌스 신원 인증" \
  --admin 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

# 5. CA 인증서 추가 (온체인에 등록한 각 CA마다)
python scripts/admin.py add-ca \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 \
  --cert ~/certs/yessign-ca.der \
  --name "yessignCA Class 3" \
  --description "한국 금융결제원 은행 인증서 CA"

# 6. 관리자 서명 (24시간 유효 — PR 머지 전에 서명)
python scripts/admin.py sign \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 \
  --private-key $ADMIN_PRIVATE_KEY \
  --operation register

# 7. 커밋 & PR 제출
git add services/
git commit -m "Register service: My DAO Voting (Sepolia)"
git push origin register/my-dao-voting

# 8. GitHub에서 PR 생성
#    제목: [Register] 11155111 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 - My DAO Voting
```

### 2. CA 추가

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
# PR 제목: [AddCA] 11155111 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 - New CA Name
```

### 3. CA 제거

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
# PR 제목: [RemoveCA] 11155111 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 - Old CA Name
```

### 4. 서비스 정보 수정

```bash
git checkout -b update/description
# service.json 편집 (name, description, website, CA instructions 등)
# 주의: admin, created_at은 불변 필드이므로 수정 불가

python scripts/admin.py sign \
  --chain-id 11155111 \
  --registry 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 \
  --private-key $ADMIN_PRIVATE_KEY \
  --operation update

git add services/
git commit -m "Update service info"
git push origin update/description
# PR 제목: [Update] 11155111 0xe7f1725e7734ce288f8367e1bb143e90bb3f0512 - My DAO Voting
```

## CI 검증 (7-Layer Validation)

`services/` 하위 파일이 변경된 PR에 대해 자동으로 실행됩니다:

| Layer | 검증 | 설명 |
|-------|------|------|
| 1 | **PR Scope** | 하나의 서비스 디렉토리만 수정했는지 |
| 2 | **PR Title** | `[Register\|AddCA\|RemoveCA\|Update] {chainId} {addr} - {name}` 형식 |
| 3 | **DER Certificate** | X.509 파싱, SPKI 해시 일치, 만료, CA 여부 |
| 4 | **service.json** | JSON 스키마, cas ↔ certs 교차 참조 |
| 5 | **Signature** | Ethereum 서명 복원, admin 일치, 24시간 만료 |
| 6 | **Immutable Fields** | 업데이트 시 admin, created_at 변경 불가 |
| 7 | **Operation** | PR 제목의 operation과 실제 변경사항 일치 |

**검증 통과 시**: PR이 자동으로 squash merge 됩니다.

## 보안 모델

| 위협 | 대응 |
|------|------|
| 저장소에서 잘못된 인증서 제공 | 프로버가 `SHA-256(SPKI) == 온체인 해시` 검증 |
| 저장소 접속 불가 | 로컬 캐시에서 이전에 검증된 인증서 사용 |
| 중간자 공격 | 해시 검증으로 변조 감지 |
| 관리자 사칭 PR | Ethereum 주소 서명 검증 (24시간 만료) |
| 서명 리플레이 공격 | Unix timestamp + operation 타입으로 방지 |
| 불변 필드 변조 | CI에서 base 브랜치와 비교하여 변경 감지 |
| 여러 서비스 동시 수정 | PR scope check (1 디렉토리만 허용) |
| 악성 DER 파일 | 10KB 초과 시 거부 (에러) + X.509 파싱 검증 |
| 만료 인증서 등록 | 만료일 검증 (90일 이내 경고) |

## 라이선스

MIT
