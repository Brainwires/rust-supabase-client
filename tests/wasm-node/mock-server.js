const http = require('node:http');

const MOCK_USER = {
  id: 'user-123',
  aud: 'authenticated',
  role: 'authenticated',
  email: 'test@example.com',
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

const MOCK_SESSION = {
  access_token: 'mock-access-token',
  refresh_token: 'mock-refresh-token',
  expires_in: 3600,
  expires_at: 9999999999,
  token_type: 'bearer',
  user: MOCK_USER,
};

const MOCK_AUTH_RESPONSE = {
  user: MOCK_USER,
  session: MOCK_SESSION,
};

const MOCK_ROWS = [
  { id: 1, name: 'Alice' },
  { id: 2, name: 'Bob' },
];

const MOCK_BUCKETS = [
  { id: 'avatars', name: 'avatars', public: true, created_at: '2024-01-01T00:00:00Z', updated_at: '2024-01-01T00:00:00Z' },
  { id: 'documents', name: 'documents', public: false, created_at: '2024-01-01T00:00:00Z', updated_at: '2024-01-01T00:00:00Z' },
];

const MOCK_BUCKET = {
  id: 'avatars',
  name: 'avatars',
  public: true,
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

const MOCK_FUNCTION_RESPONSE = { result: 'ok', data: { message: 'Hello from edge function' } };

const MOCK_GRAPHQL_RESPONSE = {
  data: { userCollection: { edges: [{ node: { id: '1', name: 'Alice' } }] } },
  errors: [],
};

/**
 * Create a mock Supabase HTTP server.
 * @param {string} apiKey - Expected apikey header value
 * @returns {Promise<{ url: string, server: http.Server, setResponse: Function, requestLog: Array, close: Function }>}
 */
async function createMockServer(apiKey) {
  const requestLog = [];
  const routes = new Map();

  /**
   * Set a route response.
   * @param {string} method - HTTP method (GET, POST, PATCH, DELETE)
   * @param {string} path - Exact path or path prefix to match
   * @param {number|object|function} statusOrHandler - Status code, response object { status, body, headers }, or handler function
   * @param {*} [body] - Response body (when first arg is status code)
   */
  function setResponse(method, path, statusOrHandler, body) {
    if (typeof statusOrHandler === 'function') {
      routes.set(`${method}:${path}`, statusOrHandler);
    } else if (typeof statusOrHandler === 'number') {
      routes.set(`${method}:${path}`, { status: statusOrHandler, body: body !== undefined ? body : '' });
    } else {
      routes.set(`${method}:${path}`, statusOrHandler);
    }
  }

  // Pre-configure default responses for all endpoint families

  // Auth
  setResponse('POST', '/auth/v1/signup', { status: 200, body: MOCK_SESSION });
  setResponse('POST', '/auth/v1/token', { status: 200, body: MOCK_SESSION });
  setResponse('POST', '/auth/v1/otp', { status: 200, body: '' });
  setResponse('GET', '/auth/v1/user', { status: 200, body: MOCK_USER });
  setResponse('POST', '/auth/v1/logout', { status: 200, body: '' });
  setResponse('POST', '/auth/v1/recover', { status: 200, body: '' });

  // PostgREST (prefix match on /rest/v1/)
  setResponse('GET', '/rest/v1/', { status: 200, body: MOCK_ROWS });
  setResponse('POST', '/rest/v1/', { status: 201, body: MOCK_ROWS });
  setResponse('PATCH', '/rest/v1/', { status: 200, body: MOCK_ROWS });
  setResponse('DELETE', '/rest/v1/', { status: 200, body: MOCK_ROWS });

  // Storage
  setResponse('GET', '/storage/v1/bucket', { status: 200, body: MOCK_BUCKETS });
  setResponse('GET', '/storage/v1/bucket/', { status: 200, body: MOCK_BUCKET });

  // Functions (prefix match on /functions/v1/)
  setResponse('POST', '/functions/v1/', { status: 200, body: MOCK_FUNCTION_RESPONSE });

  // GraphQL
  setResponse('POST', '/graphql/v1', { status: 200, body: MOCK_GRAPHQL_RESPONSE });

  function findRoute(method, pathname) {
    // Exact match first
    const exact = routes.get(`${method}:${pathname}`);
    if (exact) return exact;

    // Prefix match - find longest matching prefix
    let bestMatch = null;
    let bestLength = 0;
    for (const [key, value] of routes) {
      const colonIdx = key.indexOf(':');
      const routeMethod = key.substring(0, colonIdx);
      const routePath = key.substring(colonIdx + 1);
      if (routeMethod === method && pathname.startsWith(routePath) && routePath.length > bestLength) {
        bestMatch = value;
        bestLength = routePath.length;
      }
    }
    return bestMatch;
  }

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString();
      const url = new URL(req.url, `http://${req.headers.host}`);
      const entry = {
        method: req.method,
        path: url.pathname,
        query: url.search,
        headers: { ...req.headers },
        body,
      };
      requestLog.push(entry);

      // Validate apikey header
      if (apiKey && req.headers['apikey'] !== apiKey) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: 'Invalid API key' }));
        return;
      }

      const route = findRoute(req.method, url.pathname);

      if (!route) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ message: 'Route not found', path: url.pathname, method: req.method }));
        return;
      }

      // Function handler
      if (typeof route === 'function') {
        route(req, res, { pathname: url.pathname, query: url.searchParams, body, entry });
        return;
      }

      // Static response
      const status = route.status || 200;
      const responseHeaders = { 'Content-Type': 'application/json', ...(route.headers || {}) };
      res.writeHead(status, responseHeaders);
      const responseBody = route.body;
      if (responseBody === '' || responseBody === undefined || responseBody === null) {
        res.end('');
      } else if (typeof responseBody === 'string') {
        res.end(responseBody);
      } else {
        res.end(JSON.stringify(responseBody));
      }
    });
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({
        url: `http://127.0.0.1:${port}`,
        server,
        setResponse,
        requestLog,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

module.exports = {
  createMockServer,
  MOCK_USER,
  MOCK_SESSION,
  MOCK_AUTH_RESPONSE,
  MOCK_ROWS,
  MOCK_BUCKETS,
  MOCK_BUCKET,
  MOCK_FUNCTION_RESPONSE,
  MOCK_GRAPHQL_RESPONSE,
};
