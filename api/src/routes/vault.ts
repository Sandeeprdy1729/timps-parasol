// TIMPS-Parasol · vault.ts

import type { FastifyInstance } from 'fastify';
import { decrypt, encrypt, generateVaultKey } from '@timps/parasol';

const key = generateVaultKey();

export async function vaultRoutes(app: FastifyInstance): Promise<void> {
  app.post('/vault/encrypt', async (request, reply) => {
    const body = request.body as { plaintext: string };
    reply.send({ ciphertext: encrypt(body.plaintext, key) });
  });

  app.post('/vault/decrypt', async (request, reply) => {
    const body = request.body as { ciphertext: { iv: string; tag: string; data: string } };
    try {
      reply.send({ plaintext: decrypt(body.ciphertext, key) });
    } catch {
      reply.code(400).send({ error: 'Invalid ciphertext' });
    }
  });
}
