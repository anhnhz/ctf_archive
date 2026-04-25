const { XMLParser } = require('fast-xml-parser');
const { verifyJwt } = require('./auth');

function extractTestResults(testsuites) {
  const results = { total: 0, passed: 0, failed: 0, errors: 0, cases: [] };
  const suites = Array.isArray(testsuites) ? testsuites : [testsuites];
  for (const suite of suites) {
    const suiteName = suite['@_name'] || suite.name || 'unknown';
    const testcases = suite.testcase || suite['test-case'] || [];
    const cases = Array.isArray(testcases) ? testcases : [testcases];
    for (const tc of cases) {
      if (!tc || typeof tc !== 'object') continue;
      results.total++;
      const caseResult = {
        suite: suiteName,
        name: tc['@_name'] || tc.name || 'unnamed',
        classname: tc['@_classname'] || tc.classname || '',
        time: parseFloat(tc['@_time'] || tc.time || '0') || 0,
        status: 'passed', output: ''
      };
      if (tc.failure) {
        caseResult.status = 'failed';
        caseResult.output = typeof tc.failure === 'string' ? tc.failure : (tc.failure['#text'] || tc.failure['@_message'] || '');
        results.failed++;
      } else if (tc.error) {
        caseResult.status = 'error';
        caseResult.output = typeof tc.error === 'string' ? tc.error : (tc.error['#text'] || tc.error['@_message'] || '');
        results.errors++;
      } else {
        if (tc['system-out']) {
          caseResult.output = typeof tc['system-out'] === 'string' ? tc['system-out'] : (tc['system-out']['#text'] || '');
        }
        results.passed++;
      }
      results.cases.push(caseResult);
    }
  }
  return results;
}

async function buildsRoutes(fastify, opts) {
  fastify.addHook('preHandler', async (request, reply) => {
    if (request.url.startsWith('/api/builds') && !request.url.includes('/notify')) {
      try { request.user = await verifyJwt(request); }
      catch { return reply.code(401).send({ error: 'unauthorized' }); }
    }
  });

  fastify.post('/api/builds/:workspaceId/test-report', async (request, reply) => {
    const { workspaceId } = request.params;
    try {
      const ws = await fastify.pg.query('SELECT id, pipeline_state FROM workspaces WHERE id = $1', [workspaceId]);
      if (ws.rows.length === 0) return reply.code(404).send({ error: 'workspace not found' });

      const contentType = request.headers['content-type'] || '';
      let xmlBody;
      if (contentType.includes('application/xml') || contentType.includes('text/xml')) {
        xmlBody = request.body;
      } else if (request.body && request.body.report) {
        xmlBody = request.body.report;
      } else {
        return reply.code(400).send({ error: 'XML test report required' });
      }
      if (typeof xmlBody !== 'string') xmlBody = String(xmlBody);

      const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_', processEntities: true });
      let parsed;
      try { parsed = parser.parse(xmlBody); }
      catch { return reply.code(400).send({ error: 'invalid XML format' }); }

      const testsuites = parsed.testsuites || parsed.testsuite;
      if (!testsuites) return reply.code(400).send({ error: 'expected JUnit XML format with testsuites or testsuite root' });

      const reportData = extractTestResults(testsuites);
      const reportId = require('crypto').randomUUID();

      await fastify.redis.set(
        `report:${workspaceId}:${reportId}`,
        JSON.stringify({ id: reportId, workspace_id: parseInt(workspaceId), raw_results: reportData, parsed_at: new Date().toISOString() }),
        'EX', 3600
      );
      await fastify.redis.lpush(`reports:${workspaceId}`, reportId);

      return reply.code(201).send({
        report_id: reportId, workspace_id: parseInt(workspaceId),
        summary: { total: reportData.total, passed: reportData.passed, failed: reportData.failed, errors: reportData.errors },
        test_cases: reportData.cases
      });
    } catch (err) { return reply.code(500).send({ error: 'failed to process test report' }); }
  });

  fastify.get('/api/builds/:workspaceId/reports', async (request, reply) => {
    const { workspaceId } = request.params;
    try {
      const reportIds = await fastify.redis.lrange(`reports:${workspaceId}`, 0, 49);
      if (!reportIds || reportIds.length === 0) return reply.send({ workspace_id: parseInt(workspaceId), reports: [] });
      const reports = [];
      for (const rid of reportIds) {
        const data = await fastify.redis.get(`report:${workspaceId}:${rid}`);
        if (data) {
          const p = JSON.parse(data);
          reports.push({ id: p.id, total: p.raw_results.total, passed: p.raw_results.passed, failed: p.raw_results.failed, parsed_at: p.parsed_at });
        }
      }
      return reply.send({ workspace_id: parseInt(workspaceId), reports });
    } catch (err) { return reply.code(500).send({ error: 'failed to list reports' }); }
  });

  fastify.get('/api/builds/:workspaceId/reports/:reportId', async (request, reply) => {
    const { workspaceId, reportId } = request.params;
    try {
      const data = await fastify.redis.get(`report:${workspaceId}:${reportId}`);
      if (!data) return reply.code(404).send({ error: 'report not found' });
      const report = JSON.parse(data);
      return reply.send({ id: report.id, workspace_id: report.workspace_id, results: report.raw_results, parsed_at: report.parsed_at });
    } catch (err) { return reply.code(500).send({ error: 'failed to get report' }); }
  });

  fastify.post('/api/builds/:workspaceId/notify', async (request, reply) => {
    const { workspaceId } = request.params;
    const { event_type, payload, hmac_signature } = request.body || {};
    if (!event_type || typeof event_type !== 'string') return reply.code(400).send({ error: 'event_type is required' });

    try {
      const event = JSON.stringify({
        workspace_id: parseInt(workspaceId),
        event_type,
        payload: payload || {},
        hmac_signature: hmac_signature || '',
        published_at: Date.now()
      });
      await fastify.redis.lpush('darkharbor:event_queue', event);
      return reply.send({ queued: true, workspace_id: parseInt(workspaceId) });
    } catch (err) {
      return reply.code(500).send({ error: 'event_publish_failed' });
    }
  });
}

module.exports = buildsRoutes;
