const http = require('http');
const { createVerifier } = require('fast-jwt');
const { fetchJwksMap, invalidate: invalidateJwks } = require('../lib/jwks-fetcher');
const { verifyJwt } = require('./auth');

// Cache key builder keyed only by JWT `kid`. Different tokens sharing the same
// kid will collide, which is desirable for the verifier cache: once a kid has
// been verified once, later requests with the same kid short-circuit to the
// cached payload.
function cacheKeyBuilder(token) {
  try {
    const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
    return String(header.kid || 'no-kid');
  } catch (e) {
    return 'parse-error';
  }
}

// One verifier per kid. The per-kid verifier is long-lived so its internal
// LRU cache persists across requests.
const _verifiers = new Map();

async function resolveVerifier(kid) {
  const jwks = await fetchJwksMap();
  const entry = jwks[kid];
  if (!entry) return null;
  let ver = _verifiers.get(kid);
  if (!ver) {
    ver = createVerifier({
      key: entry.pem,
      cache: true,
      cacheTTL: 300000,
      cacheKeyBuilder,
    });
    _verifiers.set(kid, ver);
  }
  return { verifier: ver, entry };
}

function parseHeader(token) {
  try {
    return JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
  } catch (e) {
    return null;
  }
}

function forwardSeed(body) {
  return new Promise((resolve) => {
    const payload = Buffer.from(JSON.stringify(body));
    const req = http.request(
      {
        host: process.env.POLICY_ENGINE_HOST || 'policy-engine',
        port: parseInt(process.env.POLICY_ENGINE_PORT || '5000', 10),
        path: '/internal/policy-seed',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': payload.length,
        },
      },
      (res) => {
        let out = '';
        res.on('data', (chunk) => (out += chunk));
        res.on('end', () => resolve({ status: res.statusCode, body: out }));
      }
    );
    req.on('error', () => resolve({ status: 502, body: '{"error":"policy_engine_unreachable"}' }));
    req.setTimeout(5000, () => req.destroy(new Error('timeout')));
    req.write(payload);
    req.end();
  });
}


async function policyProxyRoutes(fastify, opts) {
  fastify.addHook('preHandler', async (request, reply) => {
    const u = request.raw && request.raw.url ? request.raw.url : request.url;
    if (request.routerPath && !request.routerPath.startsWith('/api/policy/') && !request.routerPath.startsWith('/internal/policy-seed')) return;
    if (!request.routerPath && !u.includes('policy')) return;
    try {
      request.user = await verifyJwt(request);
    } catch (e) {
      return reply.code(401).send({ error: 'unauthorized', detail: e.message });
    }
  });

  fastify.post('/internal/policy-seed', async (request, reply) => {
    const { workspace_id, report_id, kid } = request.body || {};
    if (!workspace_id || !report_id || !kid) {
      return reply.code(400).send({ error: 'workspace_id, report_id and kid are required' });
    }
    const out = await forwardSeed({ workspace_id, report_id, kid });
    if (out.status >= 200 && out.status < 300) {
      invalidateJwks();
    }
    try {
      return reply.code(out.status).send(JSON.parse(out.body));
    } catch (e) {
      return reply.code(out.status).send({ raw: out.body });
    }
  });

  fastify.get('/api/policy/verify', async (request, reply) => {
    const auth = request.headers['authorization'] || '';
    const match = auth.match(/^Bearer\s+([^\s]+)/i);
    if (!match) return reply.code(401).send({ error: 'missing bearer token' });
    const policyToken = request.headers['x-policy-token'] || match[1];
    const header = parseHeader(policyToken);
    if (!header || !header.kid) {
      return reply.code(400).send({ error: 'malformed policy token' });
    }
    const ver = await resolveVerifier(header.kid);
    if (!ver) return reply.code(404).send({ error: 'unknown kid', kid: header.kid });
    let payload;
    try {
      payload = await ver.verifier(policyToken);
    } catch (e) {
      return reply.code(401).send({ error: 'verify failed', detail: e.code || e.message });
    }
    return reply.send({ ok: true, kid: header.kid, role: payload.role, payload });
  });

}

module.exports = policyProxyRoutes;
