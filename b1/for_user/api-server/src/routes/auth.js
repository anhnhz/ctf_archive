const buildGetJwks = require('get-jwks');
const { createVerifier, createSigner } = require('fast-jwt');
const crypto = require('crypto');

const JWKS_ISSUER = process.env.JWKS_ISSUER || 'https://auth.darkharbor.internal';
const LOCAL_JWT_KEY = crypto.createHmac('sha256', process.env.HMAC_SECRET || 'fallback').update('darkharbor-local-jwt').digest('hex');
let getJwks;

function initJwks() {
  if (!getJwks) {
    getJwks = buildGetJwks({ jwksPath: '/.well-known/jwks.json', max: 100, ttl: 60000 });
  }
  return getJwks;
}

async function verifyJwt(request) {
  const authHeader = request.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) throw new Error('missing authorization header');
  const token = authHeader.substring(7);
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('malformed token');

  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());

  if (header.alg === 'HS256' && !header.iss) {
    const verifier = createVerifier({ key: LOCAL_JWT_KEY, algorithms: ['HS256'] });
    const payload = verifier(token);
    if (payload.iss !== 'darkharbor-local') throw new Error('invalid local issuer');
    return payload;
  }

  if (!header.iss || typeof header.iss !== 'string' || (!header.iss.startsWith('http://') && !header.iss.startsWith('https://'))) throw new Error('invalid issuer scheme');
  const jwks = initJwks();
  const publicKey = await jwks.getPublicKey({ kid: header.kid, alg: header.alg, domain: header.iss });
  const verifier = createVerifier({ key: publicKey, allowedIss: [JWKS_ISSUER], algorithms: [header.alg] });
  return verifier(token);
}

function generateLocalToken(workspaceName, role, accountId) {
  const signer = createSigner({ key: LOCAL_JWT_KEY, algorithm: 'HS256', iss: 'darkharbor-local', expiresIn: 86400000 });
  return signer({ sub: workspaceName, role: role || 'workspace_user', workspace: workspaceName, account_id: accountId || '' });
}

async function authRoutes(fastify, opts) {
  fastify.post('/api/auth/register', async (request, reply) => {
    const { workspace_name } = request.body || {};
    const prefix = (typeof workspace_name === 'string') ? workspace_name.replace(/[^a-zA-Z0-9_-]/g, '').substring(0, 24) : '';
    const suffix = crypto.randomBytes(8).toString('hex');
    const sanitized = prefix ? `${prefix}-${suffix}` : `ws-${suffix}`;

    const accountId = crypto.randomBytes(12).toString('hex');
    const token = generateLocalToken(sanitized, 'workspace_user', accountId);
    const ownerToken = crypto.randomBytes(16).toString('hex');
    try {
      const result = await fastify.pg.query(
        'INSERT INTO workspaces (name, owner_token, account_id) VALUES ($1, $2, $3) RETURNING id, name, pipeline_state', [sanitized, ownerToken, accountId]
      );
      return reply.code(201).send({ workspace: result.rows[0], token, owner_token: ownerToken });
    } catch (err) {
      if (err.code === '23505') return reply.code(409).send({ error: 'workspace already exists' });
      return reply.code(500).send({ error: 'registration failed' });
    }
  });

  fastify.post('/api/auth/login', async (request, reply) => {
    const { workspace_id, owner_token } = request.body || {};
    if (!workspace_id || !owner_token) return reply.code(400).send({ error: 'workspace_id and owner_token are required' });
    try {
      const result = await fastify.pg.query(
        'SELECT id, name, pipeline_state, account_id FROM workspaces WHERE id = $1 AND owner_token = $2', [workspace_id, owner_token]
      );
      if (result.rows.length === 0) return reply.code(401).send({ error: 'invalid credentials' });
      const ws = result.rows[0];
      const token = generateLocalToken(ws.name, 'workspace_user', ws.account_id);
      return reply.send({ workspace: ws, token });
    } catch (err) { return reply.code(500).send({ error: 'login failed' }); }
  });

  fastify.post('/api/auth/verify', async (request, reply) => {
    try {
      const payload = await verifyJwt(request);
      return reply.send({ valid: true, sub: payload.sub, role: payload.role, workspace: payload.workspace, iss: payload.iss });
    } catch (err) { return reply.code(401).send({ valid: false, error: err.message }); }
  });
}

authRoutes.verifyJwt = verifyJwt;
module.exports = authRoutes;
