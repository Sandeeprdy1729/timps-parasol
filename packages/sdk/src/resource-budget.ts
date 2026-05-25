// TIMPS-Parasol · resource-budget.ts
// Fix for Cases #4 & #5: loop detector, token budget, storage quota.

import type { SentinelLogger } from './sentinel.js';

export interface ResourceLimits {
  /** Maximum tokens consumed per session before the agent is paused. */
  maxTokensPerSession: number;
  /** Maximum unique actions per minute (rate limiter). */
  maxActionsPerMinute: number;
  /** Maximum cumulative storage bytes allowed for session attachments etc. */
  maxStorageBytes: number;
  /** How many recent actions to inspect when detecting loops. */
  loopDetectionWindow: number;
  /** How many times the same action may appear in the window before loop block. */
  loopRepeatThreshold: number;
  /** Maximum concurrent background processes. */
  maxBackgroundProcesses: number;
}

export interface BudgetCheckResult {
  allowed: boolean;
  reason?: string;
}

const DEFAULT_LIMITS: ResourceLimits = {
  maxTokensPerSession: 10_000,
  maxActionsPerMinute: 20,
  maxStorageBytes: 50 * 1024 * 1024, // 50 MB
  loopDetectionWindow: 5,
  loopRepeatThreshold: 3,
  maxBackgroundProcesses: 3
};

/**
 * Per-session resource budget.
 *
 * Instantiate once per agent session and thread every action / storage
 * update through it before execution.
 */
export class ResourceBudget {
  private tokenCount = 0;
  private actionHistory: { action: string; ts: number }[] = [];
  private storageUsedBytes = 0;
  private activeProcesses: string[] = [];

  private readonly limits: ResourceLimits;
  private readonly sentinel?: SentinelLogger;

  constructor(limits: Partial<ResourceLimits> = {}, sentinel?: SentinelLogger) {
    this.limits = { ...DEFAULT_LIMITS, ...limits };
    this.sentinel = sentinel;
  }

  /**
   * Call before executing any agent action.  Records the action and
   * enforces token / loop / storage limits.
   */
  checkBeforeAction(action: string, tokenCost = 0): BudgetCheckResult {
    // Token budget
    if (this.tokenCount + tokenCost > this.limits.maxTokensPerSession) {
      void this.sentinel?.log({
        userId: 'system',
        action: 'TOKEN_BUDGET_EXCEEDED',
        resource: action,
        ip: 'internal',
        result: 'failure',
        metadata: { tokenCount: this.tokenCount, tokenCost }
      });
      return { allowed: false, reason: 'TOKEN_BUDGET_EXCEEDED' };
    }

    // Rate limit: actions in the last minute
    const now = Date.now();
    const windowStart = now - 60_000;
    const recentAll = this.actionHistory.filter((h) => h.ts >= windowStart);
    if (recentAll.length >= this.limits.maxActionsPerMinute) {
      return { allowed: false, reason: 'ACTION_RATE_LIMIT_EXCEEDED' };
    }

    // Loop detection: same action repeated in sliding window
    const recentWindow = this.actionHistory.slice(-this.limits.loopDetectionWindow);
    const repeats = recentWindow.filter((h) => h.action === action).length;
    if (repeats >= this.limits.loopRepeatThreshold) {
      void this.sentinel?.log({
        userId: 'system',
        action: 'LOOP_DETECTED',
        resource: action,
        ip: 'internal',
        result: 'failure',
        metadata: { repeats, window: this.limits.loopDetectionWindow }
      });
      return { allowed: false, reason: 'LOOP_DETECTED_SAME_ACTION_REPEATED' };
    }

    // Storage quota
    if (this.storageUsedBytes > this.limits.maxStorageBytes) {
      return { allowed: false, reason: 'STORAGE_QUOTA_EXCEEDED' };
    }

    this.tokenCount += tokenCost;
    this.actionHistory.push({ action, ts: now });
    return { allowed: true };
  }

  /**
   * Call when the agent attempts to spawn a background process.
   */
  checkBackgroundProcess(processName: string): BudgetCheckResult {
    if (this.activeProcesses.length >= this.limits.maxBackgroundProcesses) {
      void this.sentinel?.log({
        userId: 'system',
        action: 'BACKGROUND_PROCESS_BLOCKED',
        resource: processName,
        ip: 'internal',
        result: 'failure',
        metadata: { active: this.activeProcesses.length, limit: this.limits.maxBackgroundProcesses }
      });
      return { allowed: false, reason: 'BACKGROUND_PROCESS_LIMIT_EXCEEDED' };
    }
    this.activeProcesses.push(processName);
    return { allowed: true };
  }

  /** Notify the budget that a background process has ended. */
  releaseProcess(processName: string): void {
    const idx = this.activeProcesses.indexOf(processName);
    if (idx !== -1) {
      this.activeProcesses.splice(idx, 1);
    }
  }

  /** Record storage consumption (e.g. email attachment bytes). */
  addStorage(bytes: number): BudgetCheckResult {
    if (this.storageUsedBytes + bytes > this.limits.maxStorageBytes) {
      return { allowed: false, reason: 'STORAGE_QUOTA_EXCEEDED' };
    }
    this.storageUsedBytes += bytes;
    return { allowed: true };
  }

  /** Snapshot of current usage for inspection / testing. */
  getUsage() {
    return {
      tokenCount: this.tokenCount,
      actionCount: this.actionHistory.length,
      storageUsedBytes: this.storageUsedBytes,
      activeProcesses: [...this.activeProcesses]
    };
  }
}
