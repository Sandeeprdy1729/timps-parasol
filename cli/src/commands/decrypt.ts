// TIMPS-Parasol · decrypt.ts

import { readFileSync, writeFileSync } from 'node:fs';
import chalk from 'chalk';
import { decrypt } from '@timps/parasol';
import { audit, loadConfig } from './common.js';

export function registerDecryptCommand(program: { command: (name: string) => any }): void {
  program
    .command('decrypt <file>')
    .description('Decrypt <file>.parasol back to original file')
    .action((file: string) => {
      const config = loadConfig();
      const encrypted = JSON.parse(readFileSync(file, 'utf8')) as {
        iv: string;
        tag: string;
        data: string;
      };
      const decrypted = decrypt(encrypted, Buffer.from(config.key, 'base64'));
      const target = file.replace(/\.parasol$/, '');
      writeFileSync(target, decrypted);
      audit({ action: 'decrypt', file: target });
      console.log(chalk.green(`Decrypted ${file} -> ${target}`));
    });
}
