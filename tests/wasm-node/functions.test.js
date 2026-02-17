const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');

const { WasmSupabaseClient } = require('../../pkg/node/supabase_client_wasm.js');
const { createMockServer, MOCK_FUNCTION_RESPONSE } = require('./mock-server.js');

const API_KEY = 'test-anon-key';

describe('Functions client', () => {
  let mock;

  before(async () => {
    mock = await createMockServer(API_KEY);
  });

  after(async () => {
    await mock.close();
  });

  it('invoke returns response JSON', async () => {
    const client = new WasmSupabaseClient(mock.url, API_KEY);
    const functions = client.functions();
    const result = await functions.invoke('hello', { name: 'World' });
    assert.ok(result);
    // serde_json::Value objects → serde_wasm_bindgen serializes as JS Map
    assert.ok(result instanceof Map, 'result is a Map');
    assert.equal(result.get('result'), MOCK_FUNCTION_RESPONSE.result);
    assert.equal(result.get('data').get('message'), MOCK_FUNCTION_RESPONSE.data.message);
    functions.free();
    client.free();
  });

  it('invoke sends correct body', async () => {
    mock.requestLog.length = 0;
    const client = new WasmSupabaseClient(mock.url, API_KEY);
    const functions = client.functions();
    await functions.invoke('process', { input: 42 });

    const req = mock.requestLog.find((r) => r.path === '/functions/v1/process');
    assert.ok(req, 'request was logged');
    assert.equal(req.method, 'POST');
    const body = JSON.parse(req.body);
    assert.equal(body.input, 42);
    functions.free();
    client.free();
  });

  it('server 500 causes rejection', async () => {
    const errorMock = await createMockServer(API_KEY);
    errorMock.setResponse('POST', '/functions/v1/', {
      status: 500,
      body: { message: 'Function crashed' },
    });

    const client = new WasmSupabaseClient(errorMock.url, API_KEY);
    const functions = client.functions();
    await assert.rejects(async () => await functions.invoke('broken', { data: true }));
    functions.free();
    client.free();
    await errorMock.close();
  });
});
