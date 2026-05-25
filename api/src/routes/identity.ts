// TIMPS-Parasol · identity.ts

import type { FastifyInstance } from 'fastify';
import { generateKeypair, issueJWT } from '@timps/parasol';
import { config } from '../config.js';

const users = new Map<string, { id: string; role: 'viewer' | 'editor' | 'owner' | 'admin'; publicKey?: string }>();

export async function identityRoutes(app: FastifyInstance): Promise<void> {
  app.post('/auth/register', async (request, reply) => {
    const body = request.body as { userId: string; role?: 'viewer' | 'editor' | 'owner' | 'admin'; publicKey?: string };
    if (!body?.userId) {
      reply.code(400).send({ error: 'userId required' });
      return;
    }
    const role = body.role ?? 'viewer';
    const keypair = body.publicKey ? undefined : generateKeypair();
    users.set(body.userId, { id: body.userId, role, publicKey: body.publicKey ?? keypair?.publicKey });
    reply.send({ ok: true, publicKey: body.publicKey ?? keypair?.publicKey });
  });

  app.post('/auth/login', async (request, reply) => {
    const body = request.body as { userId: string };
    const user = users.get(body?.userId ?? '');
    if (!user) {
      reply.code(401).send({ error: 'Unknown user' });
      return;
    }
    const token = issueJWT(
      { sub: user.id, role: user.role, ip: request.ip, userAgent: request.headers['user-agent'] ?? '' },
      config.jwtSecret,
      3600
    );
    reply.send({ token });
  });
}
