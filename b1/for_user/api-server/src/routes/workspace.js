const { verifyJwt } = require('./auth');

async function workspaceRoutes(fastify, opts) {
  fastify.addHook('preHandler', async (request, reply) => {
    if (request.url.startsWith('/api/workspaces')) {
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
    const { name } = request.body || {};
    const prefix = (typeof name === 'string') ? name.replace(/[^a-zA-Z0-9_-]/g, '').substring(0, 24) : '';
    const suffix = require('crypto').randomBytes(8).toString('hex');
    const sanitized = prefix ? `${prefix}-${suffix}` : `ws-${suffix}`;
    const accountId = (request.user && request.user.account_id) || require('crypto').randomBytes(12).toString('hex');
    try {
      const ownerToken = require('crypto').randomBytes(16).toString('hex');
      const result = await fastify.pg.query(
        'INSERT INTO workspaces (name, owner_token, account_id) VALUES ($1, $2, $3) RETURNING id, name, pipeline_state, created_at', [sanitized, ownerToken, accountId]
      );
      return reply.code(201).send({ workspace: result.rows[0] });
    } catch (err) {
      return reply.code(500).send({ error: 'failed to create workspace' });
    }
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
