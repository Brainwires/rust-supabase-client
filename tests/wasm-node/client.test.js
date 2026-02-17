const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const { WasmSupabaseClient } = require('../../pkg/node/supabase_client_wasm.js');

const TEST_URL = 'http://127.0.0.1:9999';
const TEST_KEY = 'test-anon-key';

describe('WasmSupabaseClient constructor', () => {
  it('creates a client with valid args', () => {
    const client = new WasmSupabaseClient(TEST_URL, TEST_KEY);
    assert.ok(client);
    client.free();
  });

  it('creates a client with https URL', () => {
    const client = new WasmSupabaseClient('https://my-project.supabase.co', TEST_KEY);
    assert.ok(client);
    client.free();
  });

  it('creates a client with trailing slash URL', () => {
    const client = new WasmSupabaseClient('http://127.0.0.1:9999/', TEST_KEY);
    assert.ok(client);
    client.free();
  });
});

describe('Sub-client factory methods', () => {
  it('.auth() returns an object', () => {
    const client = new WasmSupabaseClient(TEST_URL, TEST_KEY);
    const auth = client.auth();
    assert.ok(auth);
    assert.equal(typeof auth, 'object');
    auth.free();
    client.free();
  });

  it('.storage() returns an object', () => {
    const client = new WasmSupabaseClient(TEST_URL, TEST_KEY);
    const storage = client.storage();
    assert.ok(storage);
    assert.equal(typeof storage, 'object');
    storage.free();
    client.free();
  });

  it('.functions() returns an object', () => {
    const client = new WasmSupabaseClient(TEST_URL, TEST_KEY);
    const functions = client.functions();
    assert.ok(functions);
    assert.equal(typeof functions, 'object');
    functions.free();
    client.free();
  });

  it('.graphql() returns an object', () => {
    const client = new WasmSupabaseClient(TEST_URL, TEST_KEY);
    const graphql = client.graphql();
    assert.ok(graphql);
    assert.equal(typeof graphql, 'object');
    graphql.free();
    client.free();
  });

  it('.realtime() returns an object', () => {
    const client = new WasmSupabaseClient(TEST_URL, TEST_KEY);
    const realtime = client.realtime();
    assert.ok(realtime);
    assert.equal(typeof realtime, 'object');
    realtime.free();
    client.free();
  });
});

describe('OAuth URL generation', () => {
  const providers = ['google', 'github', 'apple', 'facebook', 'twitter', 'discord'];

  for (const provider of providers) {
    it(`get_oauth_url returns URL for ${provider}`, () => {
      const client = new WasmSupabaseClient(TEST_URL, TEST_KEY);
      const auth = client.auth();
      const url = auth.get_oauth_url(provider);
      assert.equal(typeof url, 'string');
      assert.ok(url.includes('/auth/v1/authorize'));
      assert.ok(url.includes(`provider=${provider}`));
      auth.free();
      client.free();
    });
  }

  it('get_oauth_url returns URL for custom provider', () => {
    const client = new WasmSupabaseClient(TEST_URL, TEST_KEY);
    const auth = client.auth();
    const url = auth.get_oauth_url('myidp');
    assert.equal(typeof url, 'string');
    assert.ok(url.includes('provider=myidp'));
    auth.free();
    client.free();
  });
});

describe('GraphQL set_auth', () => {
  it('set_auth does not throw', () => {
    const client = new WasmSupabaseClient(TEST_URL, TEST_KEY);
    const graphql = client.graphql();
    assert.doesNotThrow(() => graphql.set_auth('some-token'));
    graphql.free();
    client.free();
  });
});

describe('free()', () => {
  it('free() works without throwing', () => {
    const client = new WasmSupabaseClient(TEST_URL, TEST_KEY);
    assert.doesNotThrow(() => client.free());
  });
});
