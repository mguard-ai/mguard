/**
 * Witness Verification Service — HTTP server.
 *
 * Endpoints:
 *   POST /v1/keys                          Register agent public key
 *   GET  /v1/keys/:agentId                 Get agent's public key
 *   POST /v1/certificates                  Submit certificate for verification
 *   GET  /v1/certificates/:id              Get certificate + receipt
 *   GET  /v1/agents/:agentId/certificates  List agent's certificates
 *   POST /v1/antibodies                    Share antibodies
 *   GET  /v1/antibodies                    Get shared antibodies
 *   GET  /v1/stats                         Network statistics
 *   GET  /v1/witness                       Witness node info
 */

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { CertificateRegistry } from './registry';
import { WitnessServerConfig } from './types';

export function createWitnessServer(config: WitnessServerConfig = {}) {
  const requestedPort = config.port ?? 3000;
  const host = config.host ?? '0.0.0.0';
  const registry = new CertificateRegistry({ persistPath: config.persistPath });
  let actualPort = requestedPort;

  function parseBody(req: IncomingMessage): Promise<any> {
    return new Promise((resolve, reject) => {
      let body = '';
      req.on('data', (chunk: string) => { body += chunk; });
      req.on('end', () => {
        try { resolve(body ? JSON.parse(body) : {}); }
        catch { reject(new Error('Invalid JSON')); }
      });
      req.on('error', reject);
    });
  }

  function json(res: ServerResponse, status: number, data: any) {
    res.writeHead(status, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    res.end(JSON.stringify(data));
  }

  async function handleRequest(req: IncomingMessage, res: ServerResponse) {
    const url = new URL(req.url ?? '/', `http://${req.headers.host}`);
    const path = url.pathname;
    const method = req.method ?? 'GET';

    if (method === 'OPTIONS') {
      json(res, 204, '');
      return;
    }

    try {
      // POST /v1/keys
      if (method === 'POST' && path === '/v1/keys') {
        const body = await parseBody(req);
        if (!body.agentId || !body.publicKey) {
          return json(res, 400, { error: 'Missing agentId or publicKey' });
        }
        registry.registerKey(body.agentId, body.publicKey);
        return json(res, 201, { agentId: body.agentId, registered: true });
      }

      // GET /v1/keys/:agentId
      if (method === 'GET' && path.startsWith('/v1/keys/')) {
        const agentId = decodeURIComponent(path.slice('/v1/keys/'.length));
        const key = registry.getKey(agentId);
        if (!key) return json(res, 404, { error: 'Agent not found' });
        return json(res, 200, { agentId, publicKey: key });
      }

      // POST /v1/certificates
      if (method === 'POST' && path === '/v1/certificates') {
        const cert = await parseBody(req);
        if (!cert.id || !cert.signature || !cert.publicKey) {
          return json(res, 400, { error: 'Invalid certificate — missing required fields' });
        }
        const receipt = registry.submitCertificate(cert);
        return json(res, receipt.result.valid ? 201 : 200, receipt);
      }

      // GET /v1/certificates/:id
      if (method === 'GET' && path.startsWith('/v1/certificates/')) {
        const id = decodeURIComponent(path.slice('/v1/certificates/'.length));
        const entry = registry.getCertificate(id);
        if (!entry) return json(res, 404, { error: 'Certificate not found' });
        return json(res, 200, entry);
      }

      // GET /v1/agents/:agentId/certificates
      if (method === 'GET' && /^\/v1\/agents\/[^/]+\/certificates$/.test(path)) {
        const agentId = decodeURIComponent(path.split('/')[3]);
        const entries = registry.getAgentCertificates(agentId);
        return json(res, 200, { agentId, certificates: entries });
      }

      // POST /v1/antibodies
      if (method === 'POST' && path === '/v1/antibodies') {
        const body = await parseBody(req);
        if (!Array.isArray(body.antibodies)) {
          return json(res, 400, { error: 'Expected { antibodies: [...] }' });
        }
        const added = registry.submitAntibodies(body.antibodies);
        return json(res, 201, { added, total: registry.getAntibodies().length });
      }

      // GET /v1/antibodies
      if (method === 'GET' && path === '/v1/antibodies') {
        return json(res, 200, { antibodies: registry.getAntibodies() });
      }

      // GET /v1/stats
      if (method === 'GET' && path === '/v1/stats') {
        return json(res, 200, registry.getStats());
      }

      // GET /v1/witness
      if (method === 'GET' && path === '/v1/witness') {
        return json(res, 200, {
          witnessId: registry.getWitnessId(),
          publicKey: registry.getWitnessPublicKey(),
          protocol: 'witness/1.0',
        });
      }

      json(res, 404, { error: 'Not found' });
    } catch (err) {
      json(res, 500, { error: err instanceof Error ? err.message : 'Internal error' });
    }
  }

  const server = createServer(handleRequest);

  return {
    start: () => new Promise<void>((resolve) => {
      server.listen(requestedPort, host, () => {
        const addr = server.address();
        if (addr && typeof addr === 'object') {
          actualPort = addr.port;
        }
        resolve();
      });
    }),
    stop: () => new Promise<void>((resolve) => {
      server.close(() => resolve());
    }),
    get port() { return actualPort; },
    registry,
    server,
    host,
  };
}
