# TIMPS-Parasol Architecture

TIMPS-Parasol provides five defense layers: perimeter controls, identity, data vault, AI shield, and audit sentinel.

## Data flow

1. Request enters L1 perimeter middleware (rate-limit, sanitize, signature verification).
2. L2 identity verifies JWT and RBAC.
3. L3 vault encrypts/decrypts sensitive payloads.
4. L4 AI shield redacts and screens prompts/responses.
5. L5 sentinel logs every sensitive action in append-only records.
