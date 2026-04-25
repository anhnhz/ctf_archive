const fastify = require('fastify')({ logger: true });
const fastifyCors = require('@fastify/cors');
const fastifyCookie = require('@fastify/cookie');
const fastifyStatic = require('@fastify/static');
const path = require('path');
const { Pool } = require('pg');
const Redis = require('ioredis');
const http = require('http');

const authRoutes = require('./routes/auth');
const workspaceRoutes = require('./routes/workspace');
const pipelineRoutes = require('./routes/pipeline');
const buildsRoutes = require('./routes/builds');
const webhookRoutes = require('./routes/webhooks');
const deployRoutes = require('./routes/deploy');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://darkharbor:user_stack_fake_pw@postgres:5432/darkharbor',
  max: parseInt(process.env.PG_POOL_MAX || '25', 10),
});

const redis = new Redis(process.env.REDIS_URL || 'redis://redis:6379');

async function buildApp() {
  await fastify.register(fastifyCors, { origin: true, credentials: true });
  await fastify.register(fastifyCookie);

  fastify.decorate('pg', pool);
  fastify.decorate('redis', redis);

  fastify.addContentTypeParser(['application/xml', 'text/xml'], { parseAs: 'string' }, (req, body, done) => {
    done(null, body);
  });

  fastify.register(authRoutes);
  fastify.register(workspaceRoutes);
  fastify.register(pipelineRoutes);
  fastify.register(buildsRoutes);
  fastify.register(webhookRoutes);
  fastify.register(deployRoutes);

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
    const app = await buildApp();
    startMetadataServer();
    await app.listen({ port: 3000, host: '0.0.0.0' });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

main();
