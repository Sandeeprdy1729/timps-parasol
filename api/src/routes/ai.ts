// TIMPS-Parasol · ai.ts

import type { FastifyInstance } from 'fastify';
import { createAIShield } from '@timps/parasol';

const shield = createAIShield({ safeMode: true, blockThreshold: 0.7 });

export async function aiRoutes(app: FastifyInstance): Promise<void> {
  app.post('/ai/shield', async (request, reply) => {
    const body = request.body as { prompt: string; response?: string };
    const protectedPrompt = shield.protectPrompt(body.prompt);
    if (!protectedPrompt.allowed) {
      reply.code(400).send({ ok: false, error: protectedPrompt.reason, injection: protectedPrompt.injection });
      return;
    }
    const output = shield.inspectOutput(body.response ?? '');
    reply.send({ ok: true, prompt: protectedPrompt.prompt, output });
  });

  app.post('/ai/shield/config', async (request, reply) => {
    const body = request.body as { safeMode?: boolean; blockThreshold?: number };
    shield.configure(body);
    reply.send({ ok: true });
  });
}
