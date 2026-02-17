const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');

const { WasmSupabaseClient } = require('../../pkg/node/supabase_client_wasm.js');
const { createMockServer, MOCK_BUCKETS, MOCK_BUCKET } = require('./mock-server.js');

const API_KEY = 'test-anon-key';

describe('Storage client', () => {
  let mock;

  before(async () => {
    mock = await createMockServer(API_KEY);
  });

  after(async () => {
    await mock.close();
  });

  it('list_buckets returns array', async () => {
    const client = new WasmSupabaseClient(mock.url, API_KEY);
    const storage = client.storage();
    const buckets = await storage.list_buckets();
    assert.ok(Array.isArray(buckets));
    assert.equal(buckets.length, MOCK_BUCKETS.length);
    assert.equal(buckets[0].id, 'avatars');
    assert.equal(buckets[1].id, 'documents');
    storage.free();
    client.free();
  });

  it('get_bucket returns object', async () => {
    const client = new WasmSupabaseClient(mock.url, API_KEY);
    const storage = client.storage();
    const bucket = await storage.get_bucket('avatars');
    assert.ok(bucket);
    assert.equal(typeof bucket, 'object');
    assert.equal(bucket.id, MOCK_BUCKET.id);
    assert.equal(bucket.name, MOCK_BUCKET.name);
    storage.free();
    client.free();
  });

  it('404 bucket causes rejection', async () => {
    const errorMock = await createMockServer(API_KEY);
    errorMock.setResponse('GET', '/storage/v1/bucket/', {
      status: 404,
      body: { message: 'Bucket not found' },
    });

    const client = new WasmSupabaseClient(errorMock.url, API_KEY);
    const storage = client.storage();
    await assert.rejects(async () => await storage.get_bucket('nonexistent'));
    storage.free();
    client.free();
    await errorMock.close();
  });

  it('server 500 causes rejection on list_buckets', async () => {
    const errorMock = await createMockServer(API_KEY);
    errorMock.setResponse('GET', '/storage/v1/bucket', {
      status: 500,
      body: { message: 'Internal Server Error' },
    });

    const client = new WasmSupabaseClient(errorMock.url, API_KEY);
    const storage = client.storage();
    await assert.rejects(async () => await storage.list_buckets());
    storage.free();
    client.free();
    await errorMock.close();
  });
});
