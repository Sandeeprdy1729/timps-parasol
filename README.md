# TIMPS-Parasol

<img src="./timps_parasol_universal.svg" alt="TIMPS-Parasol Universal Security" />

TIMPS-Parasol is a standalone universal security product built as a 5-layer open-source shield for apps, data, and AI interactions.

## Layers

1. **L1 Perimeter Gate** — Rate limiting, sanitization, request signing, DDoS defense
2. **L2 Identity & Trust** — Ed25519, JWT, RBAC, zero-trust session claims
3. **L3 Data Vault** — AES-256-GCM, PBKDF2, per-user key isolation and rotation
4. **L4 AI Safety Shield** — PII redaction, prompt injection detection, output scanning
5. **L5 Audit Sentinel** — Append-only logs, breach alerts, webhook notifications

## Quick start

```bash
npm install
npm run build
npm test
```

### SDK

```ts
import { encrypt, decrypt, generateVaultKey } from '@timps/parasol';

const key = generateVaultKey();
const ciphertext = encrypt('hello', key);
const plaintext = decrypt(ciphertext, key);
```

### CLI

```bash
npm run build -w cli
node cli/dist/index.js init
node cli/dist/index.js encrypt ./secret.txt
```

### API

```bash
npm run build -w api
node api/dist/index.js
```

### Dashboard

```bash
npm run build -w dashboard
```
