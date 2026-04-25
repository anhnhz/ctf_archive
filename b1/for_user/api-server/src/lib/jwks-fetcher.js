const http = require('http');

const POLICY_URL = process.env.POLICY_ENGINE_URL || 'http://policy-engine:5000';
const JWKS_PATH = '/internal/.well-known/jwks.json';
const CACHE_TTL_MS = parseInt(process.env.PHASE1_JWKS_TTL_MS || '30000', 10);

let _cache = null;
let _cacheTs = 0;

function _rawFetch() {
  return new Promise((resolve, reject) => {
    const req = http.get(`${POLICY_URL}${JWKS_PATH}`, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch (e) {
          reject(new Error('jwks parse failed: ' + e.message));
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(3000, () => {
      req.destroy(new Error('jwks fetch timeout'));
    });
  });
}

async function fetchJwksMap({ force } = {}) {
  const now = Date.now();
  if (!force && _cache && now - _cacheTs < CACHE_TTL_MS) {
    return _cache;
  }
  const doc = await _rawFetch();
  const map = {};
  for (const k of doc.keys || []) {
    if (!k || !k.kid) continue;
    // Preserve the PEM exactly as the policy engine sent it. The audit banner
    // newline the engine prepends is intentional — downstream fast-jwt uses
    // the raw PEM as the verifier key material.
    map[k.kid] = { pem: k.pem, role: k.role || 'user', alg: k.alg || 'RS256' };
  }
  _cache = map;
  _cacheTs = now;
  return map;
}

function invalidate() {
  _cache = null;
  _cacheTs = 0;
}

module.exports = { fetchJwksMap, invalidate };
