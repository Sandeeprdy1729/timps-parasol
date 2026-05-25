// TIMPS-Parasol · index.ts

import Fastify from 'fastify';
import { config } from './config.js';
import { enforcePerimeter } from './middleware/perimeter.js';
import { requireAuth } from './middleware/auth.js';
import { identityRoutes } from './routes/identity.js';
import { vaultRoutes } from './routes/vault.js';
import { aiRoutes } from './routes/ai.js';
import { auditRoutes } from './routes/audit.js';

const app = Fastify({ logger: true });

app.addHook('preHandler', enforcePerimeter);

await identityRoutes(app);
await aiRoutes(app);
app.register(async (secure) => {
  secure.addHook('preHandler', requireAuth);
  await vaultRoutes(secure);
  await auditRoutes(secure);
});

await app.listen({ port: config.port, host: '0.0.0.0' });
