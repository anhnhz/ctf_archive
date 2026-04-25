const crypto = require('crypto');
const { verifyJwt } = require('./auth');

const SIGNING_KEY_SEED = process.env.SIGNING_KEY_SEED || 'user_stack_fake_seed';

function deriveSigningKey(seed, token) {
  return crypto.createHmac('sha256', seed).update(token).digest('hex');
}

async function deployRoutes(fastify, opts) {
  fastify.addHook('preHandler', async (request, reply) => {
    if (request.url.startsWith('/api/deploy')) {
      try { request.user = await verifyJwt(request); }
      catch { return reply.code(401).send({ error: 'unauthorized' }); }
    }
  });

  fastify.post('/api/deploy/:workspaceId/token', async (request, reply) => {
    const { workspaceId } = request.params;
    if (!request.user || request.user.role !== 'pipeline_admin') {
      return reply.code(403).send({ error: 'pipeline_admin role required' });
    }
    try {
      const ws = await fastify.pg.query('SELECT id, pipeline_state FROM workspaces WHERE id = $1', [workspaceId]);
      if (ws.rows.length === 0) return reply.code(404).send({ error: 'workspace not found' });
      if (ws.rows[0].pipeline_state !== 'REVIEW') {
        return reply.code(409).send({ error: 'workspace must be in REVIEW state', current_state: ws.rows[0].pipeline_state });
      }

      const token = crypto.randomUUID();
      await fastify.redis.set(
        `deploy:${workspaceId}:${token}`,
        JSON.stringify({ workspace_id: parseInt(workspaceId), created_at: Date.now() }),
        'EX', 3
      );
      return reply.code(201).send({ token, workspace_id: parseInt(workspaceId), ttl_ms: 3000 });
    } catch (err) { return reply.code(500).send({ error: 'failed to generate deploy token' }); }
  });

  fastify.post('/api/deploy/:workspaceId/use-token', async (request, reply) => {
    const { workspaceId } = request.params;
    const { token, action } = request.body || {};
    if (!token || typeof token !== 'string') return reply.code(400).send({ error: 'token is required' });
    if (!action || !['seal', 'sign'].includes(action)) return reply.code(400).send({ error: 'action must be seal or sign' });
    try {
      const sessionSeal = action === 'seal'
        ? await fastify.redis.get(`darkharbor:session_seal:${workspaceId}`)
        : null;

      const key = `deploy:${workspaceId}:${token}`;
      const data = await fastify.redis.get(key);
      if (!data) return reply.code(404).send({ error: 'token not found or expired' });
      await fastify.redis.del(key);

      const tokenData = JSON.parse(data);
      if (action === 'seal') {
        return reply.send({
          valid: true,
          workspace_id: tokenData.workspace_id,
          session_seal: sessionSeal,
          action: 'seal',
          used_at: new Date().toISOString(),
        });
      }
      const signingKey = deriveSigningKey(SIGNING_KEY_SEED, token);
      return reply.send({
        valid: true,
        workspace_id: tokenData.workspace_id,
        signing_key: signingKey,
        action: 'sign',
        used_at: new Date().toISOString(),
      });
    } catch (err) { return reply.code(500).send({ error: 'failed to validate deploy token' }); }
  });

  fastify.get('/api/deploy/:workspaceId/override-result', async (request, reply) => {
    const { workspaceId } = request.params;
    if (!request.user || request.user.role !== 'pipeline_admin') {
      return reply.code(403).send({ error: 'pipeline_admin role required' });
    }
    try {
      const data = await fastify.redis.get(`override_result:${workspaceId}`);
      if (!data) return reply.code(404).send({ error: 'no override result found' });
      return reply.send(JSON.parse(data));
    } catch (err) { return reply.code(500).send({ error: 'failed to fetch override result' }); }
  });
}

module.exports = deployRoutes;
