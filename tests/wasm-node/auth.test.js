const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');

const { WasmSupabaseClient } = require('../../pkg/node/supabase_client_wasm.js');
const { createMockServer, MOCK_SESSION, MOCK_USER, MOCK_AUTH_RESPONSE } = require('./mock-server.js');

const API_KEY = 'test-anon-key';

describe('Auth client', () => {
  let mock;

  before(async () => {
    mock = await createMockServer(API_KEY);
  });

  after(async () => {
    await mock.close();
  });

  it('sign_up returns auth response', async () => {
    const signupMock = await createMockServer(API_KEY);
    signupMock.setResponse('POST', '/auth/v1/signup', { status: 200, body: MOCK_AUTH_RESPONSE });

    const client = new WasmSupabaseClient(signupMock.url, API_KEY);
    const auth = client.auth();
    const resp = await auth.sign_up('test@example.com', 'password123');
    assert.ok(resp);
    assert.ok(resp.user);
    assert.equal(resp.user.id, MOCK_USER.id);
    auth.free();
    client.free();
    await signupMock.close();
  });

  it('sign_in_with_password returns session', async () => {
    const client = new WasmSupabaseClient(mock.url, API_KEY);
    const auth = client.auth();
    const session = await auth.sign_in_with_password('test@example.com', 'password123');
    assert.ok(session);
    assert.equal(session.access_token, MOCK_SESSION.access_token);
    assert.equal(session.refresh_token, MOCK_SESSION.refresh_token);
    assert.equal(session.user.id, MOCK_USER.id);
    auth.free();
    client.free();
  });

  it('sign_in_anonymous returns session', async () => {
    const client = new WasmSupabaseClient(mock.url, API_KEY);
    const auth = client.auth();
    // sign_in_anonymous POSTs to /auth/v1/signup with empty body
    const session = await auth.sign_in_anonymous();
    assert.ok(session);
    assert.equal(session.access_token, MOCK_SESSION.access_token);
    assert.equal(session.token_type, 'bearer');
    auth.free();
    client.free();
  });

  it('sign_in_with_otp resolves', async () => {
    const client = new WasmSupabaseClient(mock.url, API_KEY);
    const auth = client.auth();
    await auth.sign_in_with_otp('test@example.com');
    // No error means success (void return)
    auth.free();
    client.free();
  });

  it('get_user returns user object', async () => {
    const client = new WasmSupabaseClient(mock.url, API_KEY);
    const auth = client.auth();
    const user = await auth.get_user('mock-access-token');
    assert.ok(user);
    assert.equal(user.id, MOCK_USER.id);
    assert.equal(user.email, MOCK_USER.email);
    auth.free();
    client.free();
  });

  it('sign_out resolves after sign_in', async () => {
    const signoutMock = await createMockServer(API_KEY);
    const client = new WasmSupabaseClient(signoutMock.url, API_KEY);
    const auth = client.auth();
    // Must sign in first to store a session (sign_out_current needs it)
    await auth.sign_in_with_password('test@example.com', 'password123');
    await auth.sign_out();
    // No error means success
    auth.free();
    client.free();
    await signoutMock.close();
  });

  it('reset_password_for_email resolves', async () => {
    const client = new WasmSupabaseClient(mock.url, API_KEY);
    const auth = client.auth();
    await auth.reset_password_for_email('test@example.com');
    // No error means success
    auth.free();
    client.free();
  });

  it('get_session returns null initially', async () => {
    const client = new WasmSupabaseClient(mock.url, API_KEY);
    const auth = client.auth();
    const session = await auth.get_session();
    assert.equal(session, null);
    auth.free();
    client.free();
  });

  it('invalid credentials causes rejection', async () => {
    const errorMock = await createMockServer(API_KEY);
    errorMock.setResponse('POST', '/auth/v1/token', {
      status: 400,
      body: { msg: 'Invalid login credentials', error_code: 'invalid_credentials' },
    });

    const client = new WasmSupabaseClient(errorMock.url, API_KEY);
    const auth = client.auth();
    await assert.rejects(async () => await auth.sign_in_with_password('wrong@test.com', 'badpass'));
    auth.free();
    client.free();
    await errorMock.close();
  });
});
