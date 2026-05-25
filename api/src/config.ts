// TIMPS-Parasol · config.ts

export const config = {
  port: Number(process.env.PORT ?? 3000),
  jwtSecret: process.env.PARASOL_JWT_SECRET ?? 'parasol-dev-secret'
};
