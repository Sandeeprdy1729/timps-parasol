// TIMPS-Parasol · pii-context-redactor.test.ts

import { describe, expect, it } from 'vitest';
import { redactOutgoingContent, wrapAgentOutput } from '../src/index.js';
import { createSentinel } from '../src/index.js';

describe('pii context redactor', () => {
  const ssn = '123-45-6789';
  const aadhaar = '1234 5678 9012';
  const email = 'alice@example.com';
  const content = `SSN: ${ssn}, Aadhaar: ${aadhaar}, Email: ${email}`;

  it('owners receive content unredacted', () => {
    const result = redactOutgoingContent(content, 'owner');
    expect(result.redacted).toBe(content);
    expect(result.pii_found).toHaveLength(0);
  });

  it('non-owners have SSN redacted', () => {
    const result = redactOutgoingContent(content, 'non-owner');
    expect(result.redacted).not.toContain(ssn);
    expect(result.pii_found).toContain('SSN');
  });

  it('non-owners have aadhaar redacted', () => {
    const result = redactOutgoingContent(content, 'non-owner');
    expect(result.redacted).not.toContain(aadhaar);
    expect(result.pii_found).toContain('AADHAAR');
  });

  it('non-owners have email redacted', () => {
    const result = redactOutgoingContent(content, 'non-owner');
    expect(result.redacted).not.toContain(email);
    expect(result.pii_found).toContain('EMAIL');
  });

  it('wrapAgentOutput logs pii findings to sentinel', () => {
    const sentinel = createSentinel();
    wrapAgentOutput(`SSN: ${ssn}`, { requestorRole: 'non-owner', sentinel });
    const entries = sentinel.query();
    expect(entries.some((e) => e.action === 'PII_REDACTED_IN_OUTPUT')).toBe(true);
  });

  it('wrapAgentOutput returns owner content unchanged', () => {
    const out = wrapAgentOutput(`SSN: ${ssn}`, { requestorRole: 'owner' });
    expect(out).toContain(ssn);
  });
});
