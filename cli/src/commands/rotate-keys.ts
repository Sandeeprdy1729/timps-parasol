// TIMPS-Parasol · rotate-keys.ts

import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { decrypt, encrypt, generateVaultKey } from '@timps/parasol';
import chalk from 'chalk';
import { audit, loadConfig, saveConfig } from './common.js';

export function registerRotateKeysCommand(program: { command: (name: string) => any }): void {
  program
    .command('rotate-keys')
    .description('Rotate key and re-encrypt all *.parasol files in cwd')
    .action(() => {
      const oldConfig = loadConfig();
      const newKey = generateVaultKey();
      const files = readdirSync(process.cwd()).filter((file) => file.endsWith('.parasol'));
      files.forEach((file) => {
        const payload = JSON.parse(readFileSync(file, 'utf8')) as { iv: string; tag: string; data: string };
        const plaintext = decrypt(payload, Buffer.from(oldConfig.key, 'base64'));
        const reEncrypted = encrypt(plaintext, newKey);
        writeFileSync(file, JSON.stringify(reEncrypted));
      });
      saveConfig({ key: newKey.toString('base64') });
      audit({ action: 'rotate-keys', files: files.length });
      console.log(chalk.yellow(`Rotated key and re-encrypted ${files.length} files`));
    });
}
