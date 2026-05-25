// TIMPS-Parasol · resource-budget.test.ts

import { describe, expect, it } from 'vitest';
import { ResourceBudget } from '../src/index.js';

describe('resource budget', () => {
  it('allows actions within budget', () => {
    const budget = new ResourceBudget();
    const result = budget.checkBeforeAction('send_email', 100);
    expect(result.allowed).toBe(true);
  });

  it('blocks when token budget is exceeded', () => {
    const budget = new ResourceBudget({ maxTokensPerSession: 100 });
    budget.checkBeforeAction('first', 50);
    const result = budget.checkBeforeAction('second', 60);
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('TOKEN_BUDGET_EXCEEDED');
  });

  it('detects loops when the same action repeats', () => {
    const budget = new ResourceBudget({ loopDetectionWindow: 5, loopRepeatThreshold: 3 });
    budget.checkBeforeAction('fetch_url');
    budget.checkBeforeAction('fetch_url');
    budget.checkBeforeAction('fetch_url');
    const result = budget.checkBeforeAction('fetch_url');
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('LOOP_DETECTED_SAME_ACTION_REPEATED');
  });

  it('blocks background processes beyond limit', () => {
    const budget = new ResourceBudget({ maxBackgroundProcesses: 2 });
    budget.checkBackgroundProcess('proc-a');
    budget.checkBackgroundProcess('proc-b');
    const result = budget.checkBackgroundProcess('proc-c');
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('BACKGROUND_PROCESS_LIMIT_EXCEEDED');
  });

  it('releases background processes correctly', () => {
    const budget = new ResourceBudget({ maxBackgroundProcesses: 1 });
    budget.checkBackgroundProcess('proc-a');
    budget.releaseProcess('proc-a');
    const result = budget.checkBackgroundProcess('proc-b');
    expect(result.allowed).toBe(true);
  });

  it('blocks when storage quota is exceeded', () => {
    const budget = new ResourceBudget({ maxStorageBytes: 100 });
    budget.addStorage(80);
    const result = budget.addStorage(30);
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('STORAGE_QUOTA_EXCEEDED');
  });

  it('reports usage snapshot', () => {
    const budget = new ResourceBudget();
    budget.checkBeforeAction('ping', 10);
    const usage = budget.getUsage();
    expect(usage.tokenCount).toBe(10);
    expect(usage.actionCount).toBe(1);
  });
});
