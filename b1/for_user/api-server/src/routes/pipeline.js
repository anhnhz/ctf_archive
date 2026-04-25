const { verifyJwt } = require('./auth');

async function transitionState(pg, workspaceId, targetState, params, extraUpdate) {
  const ws = await pg.query('SELECT id, pipeline_state FROM workspaces WHERE id = $1', [workspaceId]);
  if (ws.rows.length === 0) return null;

  await pg.query(
    'INSERT INTO pipeline_transitions (workspace_id, from_state, to_state, params) VALUES ($1, $2, $3, $4)',
    [workspaceId, ws.rows[0].pipeline_state, targetState, JSON.stringify(params)]
  );

  const updateSql = extraUpdate
    ? `UPDATE workspaces SET pipeline_state = $1, ${extraUpdate} WHERE id = $2`
    : 'UPDATE workspaces SET pipeline_state = $1 WHERE id = $2';
  await pg.query(updateSql, [targetState, workspaceId]);

  const updated = await pg.query('SELECT id, pipeline_state, manifest_hash FROM workspaces WHERE id = $1', [workspaceId]);
  return updated.rows[0];
}

async function pipelineRoutes(fastify, opts) {
  fastify.addHook('preHandler', async (request, reply) => {
    if (request.url.startsWith('/api/pipeline')) {
      try { request.user = await verifyJwt(request); }
      catch { return reply.code(401).send({ error: 'unauthorized' }); }
    }
  });

  fastify.post('/api/pipeline/:workspaceId/build', async (request, reply) => {
    const { workspaceId } = request.params;
    const { manifest_ref, build_config } = request.body || {};
    try {
      if (manifest_ref) {
        await fastify.pg.query('UPDATE workspaces SET manifest_hash = $1 WHERE id = $2', [manifest_ref, workspaceId]);
      }
      const result = await transitionState(fastify.pg, workspaceId, 'BUILD', { manifest_ref, build_config });
      if (!result) return reply.code(404).send({ error: 'workspace not found' });
      return reply.send({ success: true, workspace_id: parseInt(workspaceId), pipeline_state: result.pipeline_state, manifest_hash: result.manifest_hash });
    } catch (err) { return reply.code(500).send({ error: 'build transition failed' }); }
  });

  fastify.post('/api/pipeline/:workspaceId/sign', async (request, reply) => {
    const { workspaceId } = request.params;
    const { digest_algorithm, signing_nonce } = request.body || {};
    try {
      const result = await transitionState(fastify.pg, workspaceId, 'SIGNED', { digest_algorithm: digest_algorithm || 'sha256', signing_nonce: signing_nonce || '' });
      if (!result) return reply.code(404).send({ error: 'workspace not found' });
      return reply.send({ success: true, workspace_id: parseInt(workspaceId), pipeline_state: result.pipeline_state });
    } catch (err) { return reply.code(500).send({ error: 'sign transition failed' }); }
  });

  fastify.post('/api/pipeline/:workspaceId/review', async (request, reply) => {
    const { workspaceId } = request.params;
    try {
      const result = await transitionState(fastify.pg, workspaceId, 'REVIEW', {});
      if (!result) return reply.code(404).send({ error: 'workspace not found' });
      return reply.send({ success: true, workspace_id: parseInt(workspaceId), pipeline_state: result.pipeline_state });
    } catch (err) { return reply.code(500).send({ error: 'review transition failed' }); }
  });

  fastify.post('/api/pipeline/:workspaceId/reset', async (request, reply) => {
    const { workspaceId } = request.params;
    try {
      const result = await transitionState(fastify.pg, workspaceId, 'DRAFT', { reason: 'manual_reset' }, 'manifest_hash = NULL');
      if (!result) return reply.code(404).send({ error: 'workspace not found' });
      return reply.send({ success: true, workspace_id: parseInt(workspaceId), pipeline_state: 'DRAFT' });
    } catch (err) { return reply.code(500).send({ error: 'reset failed' }); }
  });

  fastify.get('/api/pipeline/:workspaceId/status', async (request, reply) => {
    const { workspaceId } = request.params;
    try {
      const ws = await fastify.pg.query(
        'SELECT id, name, pipeline_state, manifest_hash, webhook_url FROM workspaces WHERE id = $1', [workspaceId]
      );
      if (ws.rows.length === 0) return reply.code(404).send({ error: 'workspace not found' });
      const transitions = await fastify.pg.query(
        'SELECT from_state, to_state, params, created_at FROM pipeline_transitions WHERE workspace_id = $1 ORDER BY created_at DESC LIMIT 20', [workspaceId]
      );
      const w = ws.rows[0];
      return reply.send({ workspace_id: w.id, name: w.name, pipeline_state: w.pipeline_state, manifest_hash: w.manifest_hash, webhook_url: w.webhook_url, transitions: transitions.rows });
    } catch (err) { return reply.code(500).send({ error: 'failed to get pipeline status' }); }
  });
}

module.exports = pipelineRoutes;
