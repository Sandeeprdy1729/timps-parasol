// TIMPS-Parasol · encrypt.ts

import { readFileSync, writeFileSync } from 'node:fs';
import chalk from 'chalk';
import { encrypt } from '@timps/parasol';
import { audit, loadConfig } from './common.js';

export function registerEncryptCommand(program: { command: (name: string) => any }): void {
  program
    .command('encrypt <file>')
    .description('Encrypt file to <file>.parasol')
    .action((file: string) => {
      const config = loadConfig();
      const payload = readFileSync(file);
      const encrypted = encrypt(payload, Buffer.from(config.key, 'base64'));
      writeFileSync(`${file}.parasol`, JSON.stringify(encrypted));
      audit({ action: 'encrypt', file });
      console.log(chalk.green(`Encrypted ${file} -> ${file}.parasol`));
    });
}
