#!/usr/bin/env node
// TIMPS-Parasol · index.ts

import { Command } from 'commander';
import { registerInitCommand } from './commands/init.js';
import { registerEncryptCommand } from './commands/encrypt.js';
import { registerDecryptCommand } from './commands/decrypt.js';
import { registerAuditCommand } from './commands/audit.js';
import { registerRotateKeysCommand } from './commands/rotate-keys.js';

const program = new Command();
program.name('parasol').description('TIMPS-Parasol CLI').version('0.1.0');

registerInitCommand(program);
registerEncryptCommand(program);
registerDecryptCommand(program);
registerAuditCommand(program);
registerRotateKeysCommand(program);

program.parse();
