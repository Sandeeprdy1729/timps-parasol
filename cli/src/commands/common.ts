// TIMPS-Parasol · common.ts

import { homedir } from 'node:os';
import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateVaultKey } from '@timps/parasol';

const PARASOL_HOME = join(homedir(), '.parasol');
const CONFIG_FILE = join(PARASOL_HOME, 'config.json');
const AUDIT_FILE = join(PARASOL_HOME, 'audit.log');

export interface LocalConfig {
  key: string;
}

export function ensureParasolHome(): void {
  if (!existsSync(PARASOL_HOME)) {
    mkdirSync(PARASOL_HOME, { recursive: true });
  }
}

export function initConfig(): LocalConfig {
  ensureParasolHome();
  const config: LocalConfig = { key: generateVaultKey().toString('base64') };
  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
  return config;
}

export function saveConfig(config: LocalConfig): void {
  ensureParasolHome();
  writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
}

export function loadConfig(): LocalConfig {
  if (!existsSync(CONFIG_FILE)) {
    return initConfig();
  }
  return JSON.parse(readFileSync(CONFIG_FILE, 'utf8')) as LocalConfig;
}

export function audit(entry: Record<string, unknown>): void {
  ensureParasolHome();
  appendFileSync(AUDIT_FILE, `${JSON.stringify({ ts: new Date().toISOString(), ...entry })}\n`);
}

export function readAuditLines(): string[] {
  if (!existsSync(AUDIT_FILE)) {
    return [];
  }
  return readFileSync(AUDIT_FILE, 'utf8').split('\n').filter(Boolean);
}
