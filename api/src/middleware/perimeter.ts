// TIMPS-Parasol · perimeter.ts

import type { FastifyReply, FastifyRequest } from 'fastify';
import { createPerimeterMiddleware } from '@timps/parasol';

const perimeter = createPerimeterMiddleware({
  requestsPerMinute: 120,
  blockThreshold: 6,
  blockDurationMs: 5 * 60_000,
  maxInputLength: 4000
});

export async function enforcePerimeter(request: FastifyRequest, reply: FastifyReply): Promise<void> {
  const result = perimeter({
    ip: request.ip,
    body: typeof request.body === 'string' ? request.body : JSON.stringify(request.body ?? ''),
    headers: request.headers as Record<string, string>
  });
  if (!result.allowed) {
    reply.code(result.statusCode ?? 429).headers(result.headers ?? {}).send({ error: result.reason });
    return;
  }
}
