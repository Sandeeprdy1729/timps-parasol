// TIMPS-Parasol · init.ts

import chalk from 'chalk';
import { initConfig } from './common.js';

export function registerInitCommand(program: { command: (name: string) => any }): void {
  program
    .command('init')
    .description('Create ~/.parasol and initialize vault key')
    .action(() => {
      initConfig();
      console.log(chalk.green('Parasol initialized at ~/.parasol'));
    });
}
