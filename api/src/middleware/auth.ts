// TIMPS-Parasol · auth.ts

import type { FastifyReply, FastifyRequest } from 'fastify';
import { verifyJWT } from '@timps/parasol';
import { config } from '../config.js';

const authRequests = new Map<string, number[]>();

export async function requireAuth(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const now = Date.now();
  const key = request.ip;
  const recent = (authRequests.get(key) ?? []).filter((ts) => ts >= now - 60_000);
  recent.push(now);
  authRequests.set(key, recent);
  if (recent.length > 120) {
    reply.code(429).send({ error: 'Too many auth checks' });
    return;
  }

  const auth = request.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    reply.code(401).send({ error: 'Missing bearer token' });
    return;
  }
  try {
    const payload = verifyJWT(auth.slice('Bearer '.length), config.jwtSecret);
    (request as FastifyRequest & { user: unknown }).user = payload;
  } catch {
    reply.code(401).send({ error: 'Invalid token' });
  }
}
