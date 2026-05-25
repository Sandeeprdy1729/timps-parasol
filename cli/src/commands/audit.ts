// TIMPS-Parasol · audit.ts

import Table from 'cli-table3';
import { readAuditLines } from './common.js';

export function registerAuditCommand(program: { command: (name: string) => any }): void {
  program
    .command('audit')
    .description('Print local audit trail')
    .action(() => {
      const table = new Table({ head: ['Time', 'Action', 'File'] });
      readAuditLines().forEach((line) => {
        const entry = JSON.parse(line) as { ts: string; action?: string; file?: string };
        table.push([entry.ts, entry.action ?? '-', entry.file ?? '-']);
      });
      console.log(table.toString());
    });
}
