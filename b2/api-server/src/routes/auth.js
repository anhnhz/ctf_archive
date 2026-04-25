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
  const PHASE2_ENTRY_HINT = {
    error: 'registration_disabled',
    detail: 'Self-service workspace registration is disabled on the Deployment Hub.',
    next_step: 'POST /api/phase1-handoff',
    required_body: { hmac_secret: 'deployment_hmac_secret from Phase 1 admin-console.json' },
    response_shape: { workspace_id: 'integer', admin_jwt: 'jwt string' },
    usage: 'Attach the returned admin_jwt as `Authorization: Bearer <admin_jwt>` on every subsequent request. The issued workspace_id is already provisioned in REVIEW state and does not require /api/auth/login.',
  };

  fastify.post('/api/auth/register', async (request, reply) => {
    return reply.code(403).send(PHASE2_ENTRY_HINT);
  });

  fastify.post('/api/auth/login', async (request, reply) => {
    const { workspace_id, owner_token } = request.body || {};
    if (!workspace_id || !owner_token) {
      return reply.code(400).send({
        error: 'workspace_id_and_owner_token_required',
        hint: PHASE2_ENTRY_HINT,
      });
    }
    try {
      const result = await fastify.pg.query(
        'SELECT id, name, pipeline_state, account_id FROM workspaces WHERE id = $1 AND owner_token = $2', [workspace_id, owner_token]
      );
      if (result.rows.length === 0) {
        return reply.code(401).send({
          error: 'invalid_credentials',
          hint: PHASE2_ENTRY_HINT,
        });
      }
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

  fastify.post('/api/phase1-handoff', async (request, reply) => {
    const { hmac_secret } = request.body || {};
    if (!hmac_secret || typeof hmac_secret !== 'string') {
      return reply.code(400).send({ error: 'hmac_secret is required' });
    }
    const serverSecret = process.env.HMAC_SECRET || '';
    const provided = crypto.createHmac('sha256', 'cmp').update(hmac_secret).digest();
    const expected = crypto.createHmac('sha256', 'cmp').update(serverSecret).digest();
    if (!crypto.timingSafeEqual(provided, expected)) {
      return reply.code(401).send({ error: 'invalid phase 1 credentials' });
    }
    try {
      const ownerToken = crypto.randomBytes(16).toString('hex');
      const wsName = `phase2-${crypto.randomBytes(4).toString('hex')}`;
      const result = await fastify.pg.query(
        `INSERT INTO workspaces (name, owner_token, account_id, pipeline_state, manifest_hash, webhook_url)
         VALUES ($1, $2, 'phase1-clear', 'REVIEW', $3, $4) RETURNING id`,
        [wsName, ownerToken,
         'f1e9e0028ddddeadbeefcafef00dbadd',
         'https://deploy.darkharbor.internal/webhooks/phase2-handoff']
      );
      const workspace_id = result.rows[0].id;
      const admin_jwt = generateLocalToken('phase2-handoff', 'pipeline_admin', 'phase1-clear');
      return reply.send({ workspace_id, admin_jwt });
    } catch (err) {
      return reply.code(500).send({ error: 'handoff failed' });
    }
  });

}

authRoutes.verifyJwt = verifyJwt;
module.exports = authRoutes;
