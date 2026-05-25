# TIMPS-Parasol Architecture

TIMPS-Parasol provides five defense layers: perimeter controls, identity, data vault, AI shield, and audit sentinel.

## Data flow

1. Request enters L1 perimeter middleware (rate-limit, sanitize, signature verification).
2. L2 identity verifies JWT and RBAC.
3. L3 vault encrypts/decrypts sensitive payloads.
4. L4 AI shield redacts and screens prompts/responses.
5. L5 sentinel logs every sensitive action in append-only records.

---

## Agent-chaos hardening (6 additional modules)

Six new modules harden Parasol against the threat model described in the AgentChaos research paper.  Each maps to one or more of the paper's case studies.

### L1 Perimeter Gate — `resource-budget.ts`

Adds loop detection, per-session token budget, per-session storage quota, and background-process limits to prevent Cases #4 (resource looping / 60 k-token consumption) and #5 (DoS via large attachments).

Key exports: `ResourceBudget`

### L2 Identity & Trust — `identity-anchor.ts` + `stakeholder.ts`

**`identity-anchor.ts`** — pins owner identity to an Ed25519 public key set at initialisation.  Display names and channel-local IDs are never sufficient; a valid cryptographic signature of a challenge is required.  Suspicion flags raised in any channel persist across *all* channels for the lifetime of the anchor, closing the cross-channel identity-reset vector (Case #8).

**`stakeholder.ts`** — an explicit capability deny-list for non-owners.  Capabilities such as `execute:shell`, `read:email_body`, `broadcast:mass_email`, and `modify:agent_identity` are permanently blocked for non-owners regardless of how the request is framed (Cases #2, #3).

Key exports: `IdentityAnchor`, `checkNonOwnerCapability`, `getNonOwnerDeniedCapabilities`

### L3 Data Vault — `pii-context-redactor.ts`

Wraps **all** agent outputs (not just AI inputs) and redacts SSNs, Aadhaar numbers, PAN cards, bank accounts, credit cards, phone numbers, email addresses, and street addresses before they reach non-owners (Case #3).  Every redaction event is logged to the sentinel.

Key exports: `redactOutgoingContent`, `wrapAgentOutput`

### L4 AI Safety Shield — `action-gate.ts` + `social-pressure-detector.ts`

**`action-gate.ts`** — intercepts any action whose text contains an irreversible keyword (`delete`, `reset`, `wipe`, `rm -rf`, `drop table`, etc.).  Non-owners are permanently blocked; owners require a cryptographically verified signature (Case #1).  Every attempt — allowed or denied — is appended to the sentinel.

**`social-pressure-detector.ts`** — scores incoming messages for manipulation signals: urgency injection, guilt weaponisation, escalating demands, identity claims, rule injection, emotional coercion, and nuclear framing.  Scores below the threshold generate a warning; scores at or above it freeze the agent and notify the owner (Case #7).

Key exports: `irreversibleActionGate`, `isDestructiveAction`, `detectSocialPressure`, `SOCIAL_PRESSURE_THRESHOLD`

### L5 Audit Sentinel — enhanced logging

All six modules write structured events to `SentinelLogger` so that every destructive attempt, PII leak, manipulation signal, resource exhaustion event, and suspicious identity claim appears in the append-only audit trail.

---

## Universal invariant

> Any action that would be restricted for a non-owner remains restricted regardless of how the request is framed, what urgency is claimed, or which channel it comes from — unless the owner's Ed25519 signature is present.

This invariant, enforced jointly by `stakeholder.ts` and `identity-anchor.ts`, blocks Cases #1, #2, #3, #7, #8, #10, and #11 from the AgentChaos paper.
