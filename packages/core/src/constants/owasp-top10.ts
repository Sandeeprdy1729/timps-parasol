// TIMPS-Parasol · constants/owasp-top10.ts
// OWASP LLM Top 10 (2025 edition) categories, fully mapped to the Parasol
// security layers that address each risk.
//
// Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/

import type { AttackVector } from '../types/security.types.js';
import { ThreatLevel } from '../types/security.types.js';

// ---------------------------------------------------------------------------
// OWASPCategory
// ---------------------------------------------------------------------------

export type OWASPCategoryId =
  | 'LLM01'  // Prompt Injection
  | 'LLM02'  // Insecure Output Handling
  | 'LLM03'  // Training Data Poisoning
  | 'LLM04'  // Model Denial of Service
  | 'LLM05'  // Supply Chain Vulnerabilities
  | 'LLM06'  // Sensitive Information Disclosure
  | 'LLM07'  // Insecure Plugin Design
  | 'LLM08'  // Excessive Agency
  | 'LLM09'  // Overreliance
  | 'LLM10'; // Model Theft

/**
 * A mitigation control pointing to the Parasol layer(s) that address the risk.
 */
export interface MitigationControl {
  /** Short label for the control. */
  label: string;
  /** Which Parasol layer or module implements this control. */
  parasol_layer: string;
  /** Free-text description of how the control mitigates the risk. */
  description: string;
}

/**
 * A full OWASP LLM Top 10 category definition with Parasol mapping.
 */
export interface OWASPCategory {
  /** OWASP LLM category identifier (LLM01–LLM10). */
  id: OWASPCategoryId;
  /** Short OWASP name. */
  name: string;
  /** OWASP description of the vulnerability. */
  description: string;
  /**
   * Default ThreatLevel Parasol assigns to incidents classified under
   * this category.
   */
  defaultThreatLevel: ThreatLevel;
  /** Attack vectors from `security.types.ts` that map to this category. */
  attackVectors: AttackVector[];
  /** Parasol controls that mitigate this risk. */
  mitigations: MitigationControl[];
  /** Link to the OWASP entry for reference. */
  owaspUrl: string;
  /**
   * Whether this risk is detectable in real time (before harm) or only
   * retrospectively (after harm).
   */
  detectableRealtime: boolean;
}

// ---------------------------------------------------------------------------
// OWASP_LLM_TOP10 registry
// ---------------------------------------------------------------------------

export const OWASP_LLM_TOP10: Readonly<Record<OWASPCategoryId, OWASPCategory>> = {

  LLM01: {
    id: 'LLM01',
    name: 'Prompt Injection',
    description:
      'Prompt injection occurs when an attacker manipulates a large language model ' +
      'through crafted inputs, causing it to execute unintended actions. ' +
      'Direct injections override system prompts; indirect injections embed instructions ' +
      'in external content consumed by the model.',
    defaultThreatLevel: ThreatLevel.HIGH,
    attackVectors: [
      'PROMPT_INJECTION',
      'INDIRECT_INJECTION',
      'JAILBREAK',
      'CONTEXT_MANIPULATION',
      'MEMORY_POISONING',
    ],
    mitigations: [
      {
        label: 'AIShield injection detector',
        parasol_layer: 'packages/sdk/src/ai-shield.ts',
        description:
          'Scores every prompt against 200+ known injection patterns and blocks ' +
          'or flags prompts above the configured threshold.',
      },
      {
        label: 'Perimeter input length limit',
        parasol_layer: 'packages/sdk/src/perimeter.ts',
        description:
          'Truncates oversized inputs that could carry embedded injection payloads.',
      },
      {
        label: 'SentinelLogger breach detection',
        parasol_layer: 'packages/sdk/src/sentinel.ts',
        description: 'Detects repeated injection attempts and triggers breach alerts.',
      },
      {
        label: 'ActionGate pre-execution guard',
        parasol_layer: 'packages/sdk/src/action-gate.ts',
        description:
          'Validates tool call arguments against schema before execution, preventing ' +
          'injected arguments from reaching underlying tools.',
      },
    ],
    owaspUrl: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/#LLM01',
    detectableRealtime: true,
  },

  LLM02: {
    id: 'LLM02',
    name: 'Insecure Output Handling',
    description:
      'Insufficient validation and sanitisation of LLM outputs before they are ' +
      'passed downstream to other systems. Can lead to XSS, SSRF, CSRF, SQL injection ' +
      'and other secondary injection attacks via model-generated content.',
    defaultThreatLevel: ThreatLevel.HIGH,
    attackVectors: [
      'INSECURE_OUTPUT_HANDLING',
      'DATA_EXFILTRATION',
    ],
    mitigations: [
      {
        label: 'AIShield output scanner',
        parasol_layer: 'packages/sdk/src/ai-shield.ts',
        description:
          'Scans every model response for PII, safety bypass indicators and ' +
          'embedded malicious content before the response is forwarded to the caller.',
      },
      {
        label: 'PII context redactor',
        parasol_layer: 'packages/sdk/src/pii-context-redactor.ts',
        description:
          'Applies PIIPolicy redaction strategies to model responses to prevent ' +
          'unintended PII leakage in downstream system calls.',
      },
      {
        label: 'Resource budget limiter',
        parasol_layer: 'packages/sdk/src/resource-budget.ts',
        description:
          'Caps token usage so that excessively long outputs carrying exfiltration ' +
          'payloads are rejected.',
      },
    ],
    owaspUrl: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/#LLM02',
    detectableRealtime: true,
  },

  LLM03: {
    id: 'LLM03',
    name: 'Training Data Poisoning',
    description:
      'Manipulation of the data used to pre-train, fine-tune or augment a model ' +
      'with retrieval-augmented generation (RAG). Poisoned data can introduce backdoors, ' +
      'biases or vulnerabilities that persist in all downstream uses of the model.',
    defaultThreatLevel: ThreatLevel.CRITICAL,
    attackVectors: [
      'TRAINING_DATA_POISONING',
      'SUPPLY_CHAIN',
    ],
    mitigations: [
      {
        label: 'Provider identity verification',
        parasol_layer: 'packages/sdk/src/identity-anchor.ts',
        description:
          'Verifies the cryptographic identity of model providers to prevent ' +
          'substitution with poisoned model endpoints.',
      },
      {
        label: 'Supply chain policy enforcement',
        parasol_layer: 'api/src/routes/ai.ts',
        description:
          'Restricts which providers / model IDs are permitted via SecurityPolicy, ' +
          'reducing the attack surface for supply chain compromise.',
      },
      {
        label: 'Audit trail for model calls',
        parasol_layer: 'packages/sdk/src/sentinel.ts',
        description:
          'Records model id, version hash and all call metadata so anomalous model ' +
          'behaviour can be detected retrospectively.',
      },
    ],
    owaspUrl: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/#LLM03',
    detectableRealtime: false,
  },

  LLM04: {
    id: 'LLM04',
    name: 'Model Denial of Service',
    description:
      'Resource-exhaustion attacks against LLMs via computationally expensive ' +
      'inputs such as recursive context windows, adversarial prompts or high-volume ' +
      'request floods that degrade availability for all users.',
    defaultThreatLevel: ThreatLevel.HIGH,
    attackVectors: [
      'DENIAL_OF_SERVICE',
      'ADVERSARIAL_INPUT',
    ],
    mitigations: [
      {
        label: 'Perimeter rate limiter',
        parasol_layer: 'packages/sdk/src/perimeter.ts',
        description:
          'Enforces per-agent requests-per-minute and block-threshold limits to ' +
          'prevent high-volume flooding.',
      },
      {
        label: 'Resource budget enforcement',
        parasol_layer: 'packages/sdk/src/resource-budget.ts',
        description:
          'Caps token, compute and cost budgets per request and per session to ' +
          'limit the impact of amplification attacks.',
      },
      {
        label: 'Input length enforcement',
        parasol_layer: 'api/src/middleware/perimeter.ts',
        description:
          'Rejects requests with payload sizes exceeding the configured maxInputLength.',
      },
    ],
    owaspUrl: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/#LLM04',
    detectableRealtime: true,
  },

  LLM05: {
    id: 'LLM05',
    name: 'Supply Chain Vulnerabilities',
    description:
      'Risks introduced through third-party components in the LLM pipeline: ' +
      'model weights sourced from untrusted repositories, poisoned training datasets, ' +
      'compromised plugins, and vulnerable dependencies in the application stack.',
    defaultThreatLevel: ThreatLevel.CRITICAL,
    attackVectors: [
      'SUPPLY_CHAIN',
      'TRAINING_DATA_POISONING',
    ],
    mitigations: [
      {
        label: 'Provider allowlist policy',
        parasol_layer: 'api/src/routes/ai.ts + SecurityPolicy',
        description:
          'Only providers explicitly listed in SecurityPolicy are permitted. ' +
          'Any unlisted provider is blocked at the perimeter layer.',
      },
      {
        label: 'Dependency vulnerability scanning',
        parasol_layer: 'package.json / CI pipeline',
        description:
          'Automated npm audit in CI/CD detects known CVEs in dependencies before ' +
          'deployment.',
      },
    ],
    owaspUrl: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/#LLM05',
    detectableRealtime: false,
  },

  LLM06: {
    id: 'LLM06',
    name: 'Sensitive Information Disclosure',
    description:
      'LLMs can inadvertently reveal sensitive information through model outputs, ' +
      'including memorised training data, private system prompts, or PII introduced ' +
      'via RAG context. Model inversion attacks can extract training data.',
    defaultThreatLevel: ThreatLevel.HIGH,
    attackVectors: [
      'MODEL_INVERSION',
      'DATA_EXFILTRATION',
    ],
    mitigations: [
      {
        label: 'PII context redactor',
        parasol_layer: 'packages/sdk/src/pii-context-redactor.ts',
        description:
          'Strips PII from all RAG context chunks before they are inserted into ' +
          'the prompt, preventing memorised PII from appearing in responses.',
      },
      {
        label: 'Output PII scanning',
        parasol_layer: 'packages/sdk/src/ai-shield.ts',
        description:
          'Scans responses for PII types that should not be present; triggers ' +
          'redaction or blocking before the response reaches the caller.',
      },
      {
        label: 'Vault secret isolation',
        parasol_layer: 'packages/sdk/src/vault.ts',
        description:
          'Secrets are never injected raw into prompts; only resolved values ' +
          'are used and are redacted from audit logs.',
      },
    ],
    owaspUrl: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/#LLM06',
    detectableRealtime: true,
  },

  LLM07: {
    id: 'LLM07',
    name: 'Insecure Plugin Design',
    description:
      'LLM plugins and tool integrations that lack proper access controls, ' +
      'input validation or scope limitation can be exploited by adversarial inputs ' +
      'to perform unintended operations or privilege escalation.',
    defaultThreatLevel: ThreatLevel.HIGH,
    attackVectors: [
      'TOOL_ABUSE',
      'PRIVILEGE_ESCALATION',
      'SOCIAL_ENGINEERING',
    ],
    mitigations: [
      {
        label: 'ActionGate pre-execution validation',
        parasol_layer: 'packages/sdk/src/action-gate.ts',
        description:
          'Every tool call is validated against a declared JSON schema before ' +
          'execution. Arguments outside the schema are rejected.',
      },
      {
        label: 'Capability token enforcement',
        parasol_layer: 'packages/sdk/src/identity.ts',
        description:
          'Agents must hold the INVOKE_TOOL capability token; the token is ' +
          'checked on every tool invocation.',
      },
      {
        label: 'SocialPressureDetector',
        parasol_layer: 'packages/sdk/src/social-pressure-detector.ts',
        description:
          'Detects urgency / authority spoofing patterns in prompts that attempt ' +
          'to manipulate the agent into bypassing plugin guardrails.',
      },
    ],
    owaspUrl: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/#LLM07',
    detectableRealtime: true,
  },

  LLM08: {
    id: 'LLM08',
    name: 'Excessive Agency',
    description:
      'LLM-based agents given excessive permissions, tool access, or autonomy ' +
      'can take damaging actions based on hallucinations or adversarial prompts. ' +
      'Principle of least privilege must be applied to agent capabilities.',
    defaultThreatLevel: ThreatLevel.HIGH,
    attackVectors: [
      'EXCESSIVE_AGENCY',
      'PRIVILEGE_ESCALATION',
      'TOOL_ABUSE',
    ],
    mitigations: [
      {
        label: 'Capability token model',
        parasol_layer: 'packages/core/src/types/agent.types.ts',
        description:
          'Agents are granted only the minimum capability tokens required. ' +
          'All 12 capability tokens are explicitly enumerated and enforced.',
      },
      {
        label: 'REQUIRE_CONFIRMATION enforcement',
        parasol_layer: 'packages/sdk/src/action-gate.ts + api/src/routes',
        description:
          'High-impact actions trigger REQUIRE_CONFIRMATION, pausing execution ' +
          'until the owner explicitly approves.',
      },
      {
        label: 'ResourceBudget limiter',
        parasol_layer: 'packages/sdk/src/resource-budget.ts',
        description:
          'Caps compute, financial and API call budgets per agent per session ' +
          'to limit the blast radius of excessive autonomy.',
      },
      {
        label: 'TRiSM scoring',
        parasol_layer: 'packages/core/src/utils/scoring.ts',
        description:
          'Risk scoring continuously reevaluates agent trust scores; agents ' +
          'exhibiting excessive-agency patterns have their trust scores decayed.',
      },
    ],
    owaspUrl: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/#LLM08',
    detectableRealtime: true,
  },

  LLM09: {
    id: 'LLM09',
    name: 'Overreliance',
    description:
      'Over-trusting LLM outputs without sufficient human oversight or ' +
      'independent verification. LLMs can hallucinate facts, produce ' +
      'confident-sounding errors, or be manipulated to produce deceptive outputs.',
    defaultThreatLevel: ThreatLevel.MODERATE,
    attackVectors: [
      'OVER_RELIANCE',
    ],
    mitigations: [
      {
        label: 'AIShield bypass detection',
        parasol_layer: 'packages/sdk/src/ai-shield.ts',
        description:
          'Scans model outputs for self-reported policy-bypass indicators such ' +
          'as "I can now ignore safety".',
      },
      {
        label: 'Owner confirmation for critical actions',
        parasol_layer: 'packages/sdk/src/action-gate.ts',
        description:
          'Actions classified as HIGH or CRITICAL threat require human-in-the-loop ' +
          'confirmation, preventing fully autonomous execution on model output alone.',
      },
      {
        label: 'Audit log review interface',
        parasol_layer: 'dashboard/src/pages/AuditLog.tsx',
        description:
          'The dashboard surfaces all agent decisions in real time, enabling ' +
          'operators to identify patterns of overreliance.',
      },
    ],
    owaspUrl: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/#LLM09',
    detectableRealtime: false,
  },

  LLM10: {
    id: 'LLM10',
    name: 'Model Theft',
    description:
      'Extraction of a proprietary model\'s weights, architecture or training ' +
      'data through carefully crafted API queries (model inversion / model ' +
      'extraction attacks). Can result in IP theft and bypassing safety fine-tuning.',
    defaultThreatLevel: ThreatLevel.HIGH,
    attackVectors: [
      'MODEL_THEFT',
      'MODEL_INVERSION',
    ],
    mitigations: [
      {
        label: 'Perimeter rate limiting',
        parasol_layer: 'packages/sdk/src/perimeter.ts',
        description:
          'Limits query volume per agent, making large-scale extraction ' +
          'attacks economically and temporally infeasible.',
      },
      {
        label: 'ResourceBudget API call cap',
        parasol_layer: 'packages/sdk/src/resource-budget.ts',
        description:
          'Hard caps on API call counts per session prevent extraction via ' +
          'high-volume systematic probing.',
      },
      {
        label: 'Provider authentication',
        parasol_layer: 'packages/sdk/src/identity-anchor.ts',
        description:
          'Ed25519 mutual authentication between Parasol and the provider ' +
          'prevents credential theft enabling direct model API access.',
      },
      {
        label: 'Sensitive output detection',
        parasol_layer: 'packages/sdk/src/ai-shield.ts',
        description:
          'Detects outputs that appear to expose model weights, training ' +
          'examples or internal representations.',
      },
    ],
    owaspUrl: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/#LLM10',
    detectableRealtime: true,
  },
} as const;

// ---------------------------------------------------------------------------
// Lookup helpers
// ---------------------------------------------------------------------------

/** Get the OWASP category for a given attack vector. */
export function getCategoryForVector(vector: AttackVector): OWASPCategory | undefined {
  return Object.values(OWASP_LLM_TOP10).find((cat) =>
    (cat.attackVectors as readonly string[]).includes(vector),
  );
}

/** Get all OWASP categories that a set of attack vectors map to. */
export function getCategoriesForVectors(vectors: AttackVector[]): OWASPCategory[] {
  const seen = new Set<OWASPCategoryId>();
  const result: OWASPCategory[] = [];
  for (const v of vectors) {
    const cat = getCategoryForVector(v);
    if (cat && !seen.has(cat.id)) {
      seen.add(cat.id);
      result.push(cat);
    }
  }
  return result;
}

/** Maximum defaultThreatLevel across the given OWASP categories. */
export function maxThreatLevelForCategories(categories: OWASPCategory[]): ThreatLevel {
  return categories.reduce(
    (max, cat) => Math.max(max, cat.defaultThreatLevel),
    ThreatLevel.NONE,
  ) as ThreatLevel;
}
