// TIMPS-Parasol · audit.ts

import type { FastifyInstance } from 'fastify';
import { createSentinel } from '@timps/parasol';

const sentinel = createSentinel();

export async function auditRoutes(app: FastifyInstance): Promise<void> {
  app.addHook('onResponse', async (request, reply) => {
    await sentinel.log({
      userId: 'api-user',
      action: 'LOG_READ',
      resource: request.url,
      ip: request.ip,
      result: reply.statusCode < 400 ? 'success' : 'failure'
    });
  });

  app.get('/audit', async (_request, reply) => {
    reply.send({ entries: sentinel.query() });
  });
}
