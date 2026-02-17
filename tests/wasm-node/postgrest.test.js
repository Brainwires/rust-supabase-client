const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');

const { WasmSupabaseClient } = require('../../pkg/node/supabase_client_wasm.js');
const { createMockServer, MOCK_ROWS } = require('./mock-server.js');

const API_KEY = 'test-anon-key';

describe('PostgREST CRUD', () => {
  let mock;

  before(async () => {
    mock = await createMockServer(API_KEY);
  });

  after(async () => {
    await mock.close();
  });

  it('from_select returns array of rows', async () => {
    const client = new WasmSupabaseClient(mock.url, API_KEY);
    const rows = await client.from_select('users', '*');
    assert.ok(Array.isArray(rows));
    assert.equal(rows.length, MOCK_ROWS.length);
    // Row is a HashMap → serde_wasm_bindgen serializes as JS Map
    assert.ok(rows[0] instanceof Map, 'rows are Map objects');
    assert.equal(rows[0].get('id'), 1);
    assert.equal(rows[0].get('name'), 'Alice');
    client.free();
  });

  it('from_select sends correct headers', async () => {
    mock.requestLog.length = 0;
    const client = new WasmSupabaseClient(mock.url, API_KEY);
    await client.from_select('users', '*');

    const req = mock.requestLog.find((r) => r.path.startsWith('/rest/v1/'));
    assert.ok(req, 'request was logged');
    assert.equal(req.headers['apikey'], API_KEY);
    assert.ok(req.headers['authorization'], 'Authorization header present');
    assert.ok(req.headers['authorization'].includes('Bearer'), 'Authorization is Bearer token');
    client.free();
  });

  it('from_insert with JSON object succeeds', async () => {
    const client = new WasmSupabaseClient(mock.url, API_KEY);
    const result = await client.from_insert('users', { name: 'Charlie', email: 'charlie@test.com' });
    assert.ok(result);
    client.free();
  });

  it('from_update with eq filter succeeds', async () => {
    const client = new WasmSupabaseClient(mock.url, API_KEY);
    const result = await client.from_update('users', { name: 'Updated' }, 'id', '1');
    assert.ok(result);
    client.free();
  });

  it('from_delete with eq filter succeeds', async () => {
    const client = new WasmSupabaseClient(mock.url, API_KEY);
    const result = await client.from_delete('users', 'id', '1');
    assert.ok(result);
    client.free();
  });

  it('server 500 causes rejection on select', async () => {
    const errorMock = await createMockServer(API_KEY);
    errorMock.setResponse('GET', '/rest/v1/', { status: 500, body: 'Internal Server Error' });

    const client = new WasmSupabaseClient(errorMock.url, API_KEY);
    await assert.rejects(async () => await client.from_select('users', '*'));
    client.free();
    await errorMock.close();
  });

  it('server 401 causes rejection on select', async () => {
    const errorMock = await createMockServer(API_KEY);
    errorMock.setResponse('GET', '/rest/v1/', { status: 401, body: { message: 'Unauthorized' } });

    const client = new WasmSupabaseClient(errorMock.url, API_KEY);
    await assert.rejects(async () => await client.from_select('users', '*'));
    client.free();
    await errorMock.close();
  });

  it('from_select sends request to correct table path', async () => {
    mock.requestLog.length = 0;
    const client = new WasmSupabaseClient(mock.url, API_KEY);
    await client.from_select('cities', 'id,name');

    const req = mock.requestLog.find((r) => r.path === '/rest/v1/cities');
    assert.ok(req, 'request was sent to /rest/v1/cities');
    assert.equal(req.method, 'GET');
    client.free();
  });
});
