const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');

const { WasmSupabaseClient } = require('../../pkg/node/supabase_client_wasm.js');
const { createMockServer, MOCK_GRAPHQL_RESPONSE } = require('./mock-server.js');

const API_KEY = 'test-anon-key';

describe('GraphQL client', () => {
  let mock;

  before(async () => {
    mock = await createMockServer(API_KEY);
  });

  after(async () => {
    await mock.close();
  });

  it('execute with query returns data', async () => {
    const client = new WasmSupabaseClient(mock.url, API_KEY);
    const graphql = client.graphql();
    const data = await graphql.execute('query { userCollection { edges { node { id name } } } }', null);
    assert.ok(data);
    // serde_json::Value objects → serde_wasm_bindgen serializes as JS Map
    assert.ok(data instanceof Map, 'data is a Map');
    const collection = data.get('userCollection');
    assert.ok(collection instanceof Map);
    const edges = collection.get('edges');
    assert.ok(Array.isArray(edges));
    const node = edges[0].get('node');
    assert.equal(node.get('id'), '1');
    assert.equal(node.get('name'), 'Alice');
    graphql.free();
    client.free();
  });

  it('execute with variables passes them through', async () => {
    mock.requestLog.length = 0;
    const client = new WasmSupabaseClient(mock.url, API_KEY);
    const graphql = client.graphql();
    await graphql.execute('query ($id: ID!) { node(id: $id) { id } }', { id: '123' });

    const req = mock.requestLog.find((r) => r.path === '/graphql/v1');
    assert.ok(req, 'request was logged');
    const body = JSON.parse(req.body);
    assert.ok(body.variables);
    assert.equal(body.variables.id, '123');
    graphql.free();
    client.free();
  });

  it('execute with null variables works', async () => {
    const client = new WasmSupabaseClient(mock.url, API_KEY);
    const graphql = client.graphql();
    const data = await graphql.execute('query { __typename }', null);
    assert.ok(data);
    graphql.free();
    client.free();
  });

  it('GraphQL error response causes rejection', async () => {
    const errorMock = await createMockServer(API_KEY);
    errorMock.setResponse('POST', '/graphql/v1', {
      status: 200,
      body: {
        data: null,
        errors: [{ message: 'Syntax error in query' }],
      },
    });

    const client = new WasmSupabaseClient(errorMock.url, API_KEY);
    const graphql = client.graphql();
    await assert.rejects(async () =>
      await graphql.execute('invalid { query', null),
    );
    graphql.free();
    client.free();
    await errorMock.close();
  });
});
