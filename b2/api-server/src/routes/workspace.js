const { verifyJwt } = require('./auth');

async function workspaceRoutes(fastify, opts) {
  fastify.addHook('preHandler', async (request, reply) => {
    if (request.url.startsWith('/api/workspaces') && !(request.method === 'POST' && request.url === '/api/workspaces')) {
      try { request.user = await verifyJwt(request); }
      catch { return reply.code(401).send({ error: 'unauthorized' }); }
    }
  });

  fastify.get('/api/workspaces', async (request, reply) => {
    try {
      const accountId = request.user && request.user.account_id;
      const page = Math.max(1, parseInt(request.query.page) || 1);
      const limit = Math.min(20, Math.max(1, parseInt(request.query.limit) || 20));
      const offset = (page - 1) * limit;
      let result, countResult;
      if (accountId) {
        result = await fastify.pg.query('SELECT id, name, pipeline_state, created_at FROM workspaces WHERE account_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3', [accountId, limit, offset]);
        countResult = await fastify.pg.query('SELECT COUNT(*) FROM workspaces WHERE account_id = $1', [accountId]);
      } else {
        result = await fastify.pg.query('SELECT id, name, pipeline_state, created_at FROM workspaces ORDER BY created_at DESC LIMIT $1 OFFSET $2', [limit, offset]);
        countResult = await fastify.pg.query('SELECT COUNT(*) FROM workspaces');
      }
      const total = parseInt(countResult.rows[0].count);
      return reply.send({ workspaces: result.rows, page, limit, total, total_pages: Math.ceil(total / limit) });
    } catch (err) { return reply.code(500).send({ error: 'failed to list workspaces' }); }
  });

  fastify.post('/api/workspaces', async (request, reply) => {
    return reply.code(403).send({
      error: 'workspace_creation_disabled',
      detail: 'Manual workspace creation is not available. Phase 2 workspaces are provisioned exclusively by the phase1 handoff endpoint.',
      next_step: 'POST /api/phase1-handoff',
      required_body: { hmac_secret: 'deployment_hmac_secret from Phase 1 admin-console.json' },
      usage: 'The handoff issues a REVIEW-state workspace_id together with an admin_jwt; use the admin_jwt as Authorization: Bearer for every deploy endpoint.',
    });
  });

  fastify.get('/api/workspaces/:id', async (request, reply) => {
    const { id } = request.params;
    try {
      const result = await fastify.pg.query(
        'SELECT id, name, pipeline_state, manifest_hash, webhook_url, created_at FROM workspaces WHERE id = $1', [id]
      );
      if (result.rows.length === 0) return reply.code(404).send({ error: 'workspace not found' });
      return reply.send({ workspace: result.rows[0] });
    } catch (err) { return reply.code(500).send({ error: 'failed to get workspace' }); }
  });

  fastify.delete('/api/workspaces/:id', async (request, reply) => {
    const { id } = request.params;
    try {
      const result = await fastify.pg.query('DELETE FROM workspaces WHERE id = $1 RETURNING id', [id]);
      if (result.rows.length === 0) return reply.code(404).send({ error: 'workspace not found' });
      return reply.send({ deleted: true, id: result.rows[0].id });
    } catch (err) { return reply.code(500).send({ error: 'failed to delete workspace' }); }
  });
}

module.exports = workspaceRoutes;
