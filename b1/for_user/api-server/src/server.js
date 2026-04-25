const fastify = require('fastify')({ logger: true });
const fastifyCors = require('@fastify/cors');
const fastifyCookie = require('@fastify/cookie');
const fastifyStatic = require('@fastify/static');
const path = require('path');
const { Pool } = require('pg');
const Redis = require('ioredis');
const http = require('http');
const { createVerifier } = require('fast-jwt');

const authRoutes = require('./routes/auth');
const workspaceRoutes = require('./routes/workspace');
const pipelineRoutes = require('./routes/pipeline');
const buildsRoutes = require('./routes/builds');
const webhookRoutes = require('./routes/webhooks');
const deployRoutes = require('./routes/deploy');
const policyProxyRoutes = require('./routes/policy-proxy');
const { fetchJwksMap } = require('./lib/jwks-fetcher');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://darkharbor:harb0r_s3cret_2026@postgres:5432/darkharbor',
  max: parseInt(process.env.PG_POOL_MAX || '25', 10),
});

const redis = new Redis(process.env.REDIS_URL || 'redis://redis:6379');

const _flagVerifiers = new Map();
function _flagCacheKeyBuilder(token) {
  try {
    const h = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString());
    return String(h.kid || 'no-kid');
  } catch (e) {
    return 'parse-error';
  }
}
async function _resolveFlagVerifier(kid) {
  const jwks = await fetchJwksMap();
  const entry = jwks[kid];
  if (!entry) return null;
  let ver = _flagVerifiers.get(kid);
  if (!ver) {
    ver = createVerifier({ key: entry.pem, cache: true, cacheTTL: 300000, cacheKeyBuilder: _flagCacheKeyBuilder });
    _flagVerifiers.set(kid, ver);
  }
  return { verifier: ver, entry };
}

async function buildApp() {
  await fastify.register(fastifyCors, { origin: true, credentials: true });
  await fastify.register(fastifyCookie);

  fastify.decorate('pg', pool);
  fastify.decorate('redis', redis);

  fastify.addContentTypeParser(['application/xml', 'text/xml'], { parseAs: 'string' }, (req, body, done) => {
    done(null, body);
  });

  fastify.addHook('onRequest', async (request, reply) => {
    if (request.url.startsWith('/internal/')) {
      return reply.code(403).send({ error: 'internal path forbidden' });
    }
  });

  fastify.addHook('preHandler', async (request, reply) => {
    let decoded;
    try { decoded = decodeURIComponent(request.url); } catch (e) { return; }
    if (!decoded.includes('admin-console')) return;
    const policyToken = request.headers['x-policy-token'];
    if (!policyToken) return reply.code(401).send({ error: 'policy token required' });
    let header;
    try {
      header = JSON.parse(Buffer.from(policyToken.split('.')[0], 'base64url').toString());
    } catch (e) { return reply.code(400).send({ error: 'malformed token' }); }
    if (!header || !header.kid) return reply.code(400).send({ error: 'malformed token' });
    const ver = await _resolveFlagVerifier(header.kid);
    if (!ver) return reply.code(401).send({ error: 'unknown kid' });
    let payload;
    try { payload = await ver.verifier(policyToken); }
    catch (e) { return reply.code(401).send({ error: 'verify failed' }); }
    if (payload.role !== 'admin') return reply.code(403).send({ error: 'admin role required' });
  });

  fastify.register(authRoutes);
  fastify.register(workspaceRoutes);
  fastify.register(pipelineRoutes);
  fastify.register(buildsRoutes);
  fastify.register(webhookRoutes);
  fastify.register(deployRoutes);
  fastify.register(policyProxyRoutes);

  fastify.get('/api/health', async () => {
    return { status: 'ok', service: 'darkharbor-api', version: '1.0.0' };
  });

  await fastify.register(fastifyStatic, {
    root: path.join(__dirname, '..', 'public'),
    prefix: '/',
  });

  fastify.setNotFoundHandler((request, reply) => {
    if (request.url.startsWith('/api/') || request.url.startsWith('/build/') || request.url.startsWith('/internal/')) {
      return reply.code(404).send({ error: 'not found' });
    }
    return reply.sendFile('index.html');
  });

  return fastify;
}

function startMetadataServer() {
  const configPort = parseInt(process.env.INTERNAL_CONFIG_PORT || '6000', 10);
  const hmacSecret = process.env.HMAC_SECRET || '';

  const metadataServer = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/config') {
      const config = {
        routing: {
          '/api/*': 'api-server:3000',
          '/build/*': 'build-runner:9000',
          '/health/policy-engine': 'policy-engine:5000',
          '/internal/*': 'policy-engine:5000'
        },
        hmac_secret: hmacSecret,
        pipeline_api: '/api/pipeline'
      };
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(config));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'not found' }));
  });

  metadataServer.listen(configPort, '0.0.0.0', () => {
    console.log(`Metadata server listening on port ${configPort}`);
  });
}

async function main() {
  try {
    const fs = require('fs');
    const adminConsolePath = path.join(__dirname, '..', 'public', 'internal', 'admin-console.json');
    fs.mkdirSync(path.dirname(adminConsolePath), { recursive: true });
    fs.writeFileSync(
      adminConsolePath,
      JSON.stringify({ flag: process.env.FLAG || '', deployment_hmac_secret: process.env.HMAC_SECRET || '' }, null, 2)
    );

    const app = await buildApp();
    startMetadataServer();
    await app.listen({ port: 3000, host: '0.0.0.0' });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

main();
