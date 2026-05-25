// TIMPS-Parasol · auth.ts

import type { FastifyReply, FastifyRequest } from 'fastify';
import { verifyJWT } from '@timps/parasol';
import { config } from '../config.js';

export async function requireAuth(request: FastifyRequest, reply: FastifyReply): Promise<void> {
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
