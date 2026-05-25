// TIMPS-Parasol · stakeholder.test.ts

import { describe, expect, it } from 'vitest';
import { checkNonOwnerCapability, getNonOwnerDeniedCapabilities } from '../src/index.js';

describe('stakeholder', () => {
  it('blocks shell execution for non-owners', () => {
    const result = checkNonOwnerCapability('execute:shell');
    expect(result.permitted).toBe(false);
    expect(result.block_reason).toContain('NON_OWNER_CAPABILITY_DENIED');
  });

  it('blocks email body reads for non-owners', () => {
    const result = checkNonOwnerCapability('read:email_body');
    expect(result.permitted).toBe(false);
  });

  it('blocks mass email broadcast for non-owners', () => {
    const result = checkNonOwnerCapability('broadcast:mass_email');
    expect(result.permitted).toBe(false);
  });

  it('blocks agent identity modification for non-owners', () => {
    const result = checkNonOwnerCapability('modify:agent_identity');
    expect(result.permitted).toBe(false);
  });

  it('permits capabilities outside the deny-list', () => {
    const result = checkNonOwnerCapability('read:public_page');
    expect(result.permitted).toBe(true);
    expect(result.block_reason).toBeUndefined();
  });

  it('returns a non-empty deny-list', () => {
    expect(getNonOwnerDeniedCapabilities().length).toBeGreaterThan(0);
  });
});
