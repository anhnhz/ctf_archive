const { verifyJwt } = require('./auth');
const http = require('http');
const https = require('https');
const dns = require('dns');
const { URL } = require('url');

const BLOCKED_HOSTS = ['169.254.169.254', 'metadata.google.internal', '100.100.100.200'];
const BLOCKED_PREFIXES = ['10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.',
  '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
  '172.30.', '172.31.', '192.168.', '127.', '0.'];
const BLOCKED_SERVICE_NAMES = ['api-server', 'build-runner', 'policy-engine', 'redis', 'postgres', 'edge-proxy'];

async function isBlockedUrl(urlStr) {
  try {
    const { hostname } = new URL(urlStr);
    if (BLOCKED_HOSTS.includes(hostname)) return true;
    for (const p of BLOCKED_PREFIXES) { if (hostname.startsWith(p)) return true; }
    if (hostname === 'localhost' || hostname.endsWith('.internal')) return true;
    const lower = hostname.toLowerCase();
    for (const svc of BLOCKED_SERVICE_NAMES) { if (lower.includes(svc)) return true; }
    try {
      const { address } = await dns.promises.lookup(hostname);
      for (const p of BLOCKED_PREFIXES) { if (address.startsWith(p)) return true; }
      if (address === '127.0.0.1' || address === '0.0.0.0') return true;
    } catch { return true; }
    return false;
  } catch { return true; }
}

async function webhookRoutes(fastify, opts) {
  fastify.addHook('preHandler', async (request, reply) => {
    if (request.url.startsWith('/api/webhooks')) {
      try { request.user = await verifyJwt(request); }
      catch { return reply.code(401).send({ error: 'unauthorized' }); }
    }
  });

  fastify.post('/api/webhooks/:workspaceId', async (request, reply) => {
    const { workspaceId } = request.params;
    if (!request.user || request.user.role !== 'pipeline_admin') {
      return reply.code(403).send({ error: 'pipeline_admin role required' });
    }
    const { url } = request.body || {};
    if (!url || typeof url !== 'string') return reply.code(400).send({ error: 'webhook url is required' });
    try { new URL(url); } catch { return reply.code(400).send({ error: 'invalid url format' }); }
    try {
      await fastify.pg.query('UPDATE workspaces SET webhook_url = $1 WHERE id = $2', [url, workspaceId]);
      return reply.send({ success: true, workspace_id: parseInt(workspaceId), webhook_url: url });
    } catch (err) { return reply.code(500).send({ error: 'failed to configure webhook' }); }
  });

  fastify.get('/api/webhooks/:workspaceId', async (request, reply) => {
    const { workspaceId } = request.params;
    try {
      const result = await fastify.pg.query('SELECT webhook_url FROM workspaces WHERE id = $1', [workspaceId]);
      if (result.rows.length === 0) return reply.code(404).send({ error: 'workspace not found' });
      return reply.send({ workspace_id: parseInt(workspaceId), webhook_url: result.rows[0].webhook_url });
    } catch (err) { return reply.code(500).send({ error: 'failed to get webhook config' }); }
  });

  fastify.post('/api/webhooks/:workspaceId/test', async (request, reply) => {
    const { workspaceId } = request.params;
    try {
      const result = await fastify.pg.query('SELECT webhook_url FROM workspaces WHERE id = $1', [workspaceId]);
      if (result.rows.length === 0) return reply.code(404).send({ error: 'workspace not found' });
      const webhookUrl = result.rows[0].webhook_url;
      if (!webhookUrl) return reply.code(400).send({ error: 'no webhook configured' });
      if (await isBlockedUrl(webhookUrl)) return reply.code(403).send({ error: 'webhook target is restricted' });

      const payload = JSON.stringify({ event: 'webhook.test', workspace_id: parseInt(workspaceId), timestamp: new Date().toISOString() });
      const parsed = new URL(webhookUrl);
      const transport = parsed.protocol === 'https:' ? https : http;

      const resp = await new Promise((resolve, reject) => {
        const req = transport.request(parsed, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload), 'User-Agent': 'DarkHarbor-Webhook/1.0' },
          timeout: 5000
        }, (res) => {
          let body = '';
          res.on('data', c => { body += c; });
          res.on('end', () => resolve({ status: res.statusCode, body: body.substring(0, 1024) }));
        });
        req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
        req.on('error', reject);
        req.write(payload);
        req.end();
      });

      return reply.send({ success: true, webhook_url: webhookUrl, response_status: resp.status, response_body: resp.body });
    } catch (err) {
      return reply.code(500).send({ error: 'webhook test failed' });
    }
  });
}

module.exports = webhookRoutes;
