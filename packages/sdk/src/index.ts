// TIMPS-Parasol · index.ts

export * from './types.js';
export * from './perimeter.js';
export * from './identity.js';
export * from './vault.js';
export * from './ai-shield.js';
export * from './sentinel.js';

// --- Agent-chaos hardening modules (AgentChaos paper) ---
export * from './action-gate.js';
export * from './stakeholder.js';
export * from './pii-context-redactor.js';
export * from './resource-budget.js';
export * from './identity-anchor.js';
export * from './social-pressure-detector.js';

// --- Production semantic + intent reasoning layers ---
export * from './semantic-injection.js';
export * from './intent-exfil.js';
export * from './embedding-injection.js';