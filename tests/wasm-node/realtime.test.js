const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { WasmSupabaseClient } = require('../../pkg/node/supabase_client_wasm.js');

const TEST_URL = 'http://127.0.0.1:9999';
const TEST_KEY = 'test-anon-key';

describe('Realtime client', () => {
  it('is_connected returns false before connect', () => {
    const client = new WasmSupabaseClient(TEST_URL, TEST_KEY);
    const realtime = client.realtime();
    assert.equal(realtime.is_connected(), false);
    realtime.free();
    client.free();
  });

  it('connect rejects when server unavailable', async () => {
    // Use a URL where no WebSocket server is running
    const client = new WasmSupabaseClient('http://127.0.0.1:1', TEST_KEY);
    const realtime = client.realtime();
    await assert.rejects(async () => await realtime.connect());
    realtime.free();
    client.free();
  });
});
