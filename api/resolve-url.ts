import { resolveRedirectChainNode } from '../src/server/urlResolver';

export default async function handler(req: any, res: any) {
  try {
    let targetUrl = '';
    if (req.method === 'GET') {
      targetUrl = typeof req.query?.url === 'string' ? req.query.url : '';
    } else if (req.method === 'POST') {
      const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
      targetUrl = typeof body.url === 'string' ? body.url : '';
    } else {
      res.status(405).json({ error: 'Method not allowed' });
      return;
    }

    if (!targetUrl.trim()) {
      res.status(400).json({ error: 'Missing url parameter' });
      return;
    }

    const result = await resolveRedirectChainNode(targetUrl);
    res.status(200).json(result);
  } catch (err) {
    res.status(500).json({
      error: err instanceof Error ? err.message : 'Failed to resolve URL',
      resolved: false
    });
  }
}
