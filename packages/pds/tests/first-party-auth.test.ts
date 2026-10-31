import { createSecretKey } from 'node:crypto'
import type { IncomingMessage } from 'node:http'
import { describe, expect, it, jest } from '@jest/globals'
import { SignJWT } from 'jose'
import type { AppContext } from '../src/context.js'
import {
  authorizeFirstPartySession,
  isFirstPartyClient,
} from '../src/first-party-auth.js'

const clientId = 'https://staging-api.gems.xyz/auth/oauth-client-metadata.json'
const config = {
  firstPartyClients: [clientId],
  firstPartyNativeAuthOrigin: 'http://127.0.0.1:8080',
  firstPartyClientTemplates: [
    'https://api-preview-q{runId}.gems.xyz/auth/oauth-client-metadata.json',
  ],
}
const input = {
  identifier: 'alice.gems.xyz',
  password: 'fixture-password',
  requestUri: 'urn:ietf:params:oauth:request_uri:fixture',
}
beforeEach(() => jest.restoreAllMocks())
function fixture() {
  const jwtKey = createSecretKey(Buffer.alloc(32, 1))
  const revokeRefreshToken = jest.fn(async (_id: string) => {})
  const nativeFetch = jest
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async () =>
      Response.json({
        did: 'did:plc:alice',
        refreshJwt: await new SignJWT({ scope: 'com.atproto.refresh' })
          .setProtectedHeader({ alg: 'HS256', typ: 'refresh+jwt' })
          .setAudience('did:web:gems.xyz')
          .setSubject('did:plc:alice')
          .setJti('temporary-native-session')
          .setExpirationTime('5m')
          .sign(jwtKey),
      }),
    )
  const pending = {
    requestUri: input.requestUri,
    clientId,
    parameters: {
      state: 'oauth-state',
      login_hint: 'did:plc:alice',
      scope: 'atproto account:email',
    },
  }
  const client = {
    id: clientId,
    metadata: { token_endpoint_auth_method: 'private_key_jwt' },
  }
  const account = { did: 'did:plc:alice', handle: 'alice.gems.xyz' }
  const provider = {
    issuer: 'https://gems.xyz',
    requestManager: {
      getAuthenticated: jest.fn(async () => pending),
      get: jest.fn(async (..._args: unknown[]) => pending),
      setAuthorized: jest.fn(async () => 'one-use-code'),
    },
    clientManager: { getClient: jest.fn(async () => client) },
    deviceManager: {
      createEphemeral: jest.fn(async () => ({
        deviceId: 'device',
        deviceMetadata: { ipAddress: '127.0.0.1' },
      })),
    },
    accountManager: {
      getAccount: jest.fn(async () => ({
        account,
        authorizedClients: new Map(),
      })),
      setAuthorizedClient: jest.fn(async (..._args: unknown[]) => {}),
      upsertDeviceAccount: jest.fn(async (..._args: unknown[]) => {}),
    },
  }
  const login = jest.fn(async (_credentials: unknown) => ({
    user: { did: account.did },
    appPassword: null as unknown,
    isSoftDeleted: false,
  }))
  const ctx = {
    cfg: { oauth: { provider: config } },
    oauthProvider: provider,
    accountManager: {
      login,
      jwtKey,
      serviceDid: 'did:web:gems.xyz',
      revokeRefreshToken,
    },
  } as unknown as Pick<AppContext, 'cfg' | 'oauthProvider' | 'accountManager'>
  const req = { headers: {} } as IncomingMessage
  return {
    ctx,
    req,
    provider,
    pending,
    client,
    account,
    login,
    nativeFetch,
    revokeRefreshToken,
    [Symbol.dispose]() {
      nativeFetch.mockRestore()
    },
  }
}
describe('first-party trust boundary', () => {
  it('requires an exact configured confidential-client ID', () => {
    expect(isFirstPartyClient(clientId, config)).toBe(true)
    expect(isFirstPartyClient(clientId, {})).toBe(false)
    for (const id of [
      clientId + '?extra=1',
      clientId + '#fragment',
      clientId + '/extra',
      clientId.replace('https:', 'http:'),
      clientId.replace('gems.xyz', 'gems.xyz.evil.example'),
      clientId.replace('https://', 'https://user@'),
      'https://other.gems.xyz/auth/oauth-client-metadata.json',
    ])
      expect(isFirstPartyClient(id, config)).toBe(false)
  })
  it('allows only numeric CI runs at the complete configured hostname and path', () => {
    const candidate =
      'https://api-preview-q123.gems.xyz/auth/oauth-client-metadata.json'
    expect(isFirstPartyClient(candidate, config)).toBe(true)
    for (const id of [
      candidate.replace('123', '0'),
      candidate.replace('123', 'abc'),
      candidate.replace('123', '123.evil'),
      candidate.replace('gems.xyz', 'gemsXxyz'),
      candidate.replace('123', '123456789012345678901'),
      candidate + '/extra',
    ])
      expect(isFirstPartyClient(id, config)).toBe(false)
    expect(
      isFirstPartyClient(candidate, {
        firstPartyClientTemplates: [
          'https://api-preview-q123.gems.xyz/{runId}',
        ],
      }),
    ).toBe(false)
  })
})
it('returns only a one-use authorization response after native credential verification', async () => {
  using f = fixture()
  expect(await authorizeFirstPartySession(f.ctx, input, f.req)).toEqual({
    code: 'one-use-code',
    state: 'oauth-state',
    iss: 'https://gems.xyz',
  })
  expect(f.login).toHaveBeenCalledWith(input)
  expect(f.revokeRefreshToken).toHaveBeenCalledWith('temporary-native-session')
  expect(f.provider.requestManager.get).toHaveBeenCalledWith(
    input.requestUri,
    'device',
    clientId,
  )
  expect(f.provider.accountManager.upsertDeviceAccount).toHaveBeenCalledWith(
    'device',
    f.account.did,
  )
  expect(f.provider.accountManager.setAuthorizedClient).toHaveBeenCalledWith(
    f.account,
    f.client,
    { authorizedScopes: ['atproto', 'account:email'] },
  )
})
it('does not verify credentials or create devices for untrusted or unauthenticated requests', async () => {
  for (const failure of ['client', 'par', 'public', 'ambient'] as const) {
    using f = fixture()
    if (failure === 'client')
      f.pending.clientId = 'https://evil.example/client.json'
    if (failure === 'par')
      f.provider.requestManager.getAuthenticated.mockRejectedValue(
        new Error('unsigned'),
      )
    if (failure === 'public')
      f.client.metadata.token_endpoint_auth_method = 'none'
    if (failure === 'ambient') f.req.headers.cookie = 'ambient-session=secret'
    await expect(
      authorizeFirstPartySession(f.ctx, input, f.req),
    ).rejects.toThrow()
    expect(f.login).not.toHaveBeenCalled()
    expect(f.provider.deviceManager.createEphemeral).not.toHaveBeenCalled()
    expect(f.provider.requestManager.setAuthorized).not.toHaveBeenCalled()
  }
})
it('issues no grant or device for invalid credentials, app passwords, takedowns or account mismatch', async () => {
  for (const failure of [
    'password',
    'app-password',
    'takedown',
    'identity',
  ] as const) {
    using f = fixture()
    if (failure === 'password')
      f.login.mockRejectedValue(new Error('Invalid password'))
    if (failure === 'app-password')
      f.login.mockResolvedValue({
        user: { did: f.account.did },
        appPassword: {},
        isSoftDeleted: false,
      })
    if (failure === 'takedown')
      f.login.mockResolvedValue({
        user: { did: f.account.did },
        appPassword: null,
        isSoftDeleted: true,
      })
    if (failure === 'identity')
      f.pending.parameters.login_hint = 'did:plc:other'
    await expect(
      authorizeFirstPartySession(f.ctx, input, f.req),
    ).rejects.toThrow()
    expect(f.provider.deviceManager.createEphemeral).not.toHaveBeenCalled()
    expect(f.provider.requestManager.setAuthorized).not.toHaveBeenCalled()
  }
})

it('preserves the gatekeeper email factor and issues no OAuth grant before it succeeds', async () => {
  using f = fixture()
  f.nativeFetch.mockResolvedValueOnce(
    Response.json({ error: 'AuthFactorTokenRequired' }, { status: 401 }),
  )
  await expect(authorizeFirstPartySession(f.ctx, input, f.req)).rejects.toThrow(
    'verification code',
  )
  expect(f.provider.deviceManager.createEphemeral).not.toHaveBeenCalled()
  expect(f.provider.requestManager.setAuthorized).not.toHaveBeenCalled()
  await authorizeFirstPartySession(
    f.ctx,
    { ...input, authFactorToken: 'ABCDE-12345' },
    f.req,
  )
  const [url, request] = f.nativeFetch.mock.calls[1]
  expect(String(url)).toBe(
    'http://127.0.0.1:8080/xrpc/com.atproto.server.createSession',
  )
  expect(request?.redirect).toBe('error')
  expect(JSON.parse(request!.body as string)).toEqual({
    identifier: input.identifier,
    password: input.password,
    authFactorToken: 'ABCDE-12345',
  })
  expect(f.revokeRefreshToken).toHaveBeenCalledWith('temporary-native-session')
})
it('rejects unverifiable native authentication responses before authorizing a grant', async () => {
  using f = fixture()
  f.nativeFetch.mockResolvedValueOnce(
    Response.json({ did: 'did:plc:alice', refreshJwt: 'forged' }),
  )
  await expect(
    authorizeFirstPartySession(f.ctx, input, f.req),
  ).rejects.toThrow()
  expect(f.revokeRefreshToken).not.toHaveBeenCalled()
  expect(f.provider.requestManager.setAuthorized).not.toHaveBeenCalled()
})

it('fails closed when the configured native authenticator is missing or unavailable', async () => {
  for (const failure of [
    'missing',
    'external',
    'unavailable',
    'cleanup',
  ] as const) {
    using f = fixture()
    f.ctx.cfg.oauth.provider = { ...f.ctx.cfg.oauth.provider! }
    if (failure === 'missing')
      f.ctx.cfg.oauth.provider.firstPartyNativeAuthOrigin = undefined
    if (failure === 'external')
      f.ctx.cfg.oauth.provider.firstPartyNativeAuthOrigin =
        'https://evil.example'
    if (failure === 'unavailable')
      f.nativeFetch.mockResolvedValueOnce(
        Response.json({ error: 'Unavailable' }, { status: 503 }),
      )
    if (failure === 'cleanup')
      f.revokeRefreshToken.mockRejectedValueOnce(new Error('cleanup failed'))
    await expect(
      authorizeFirstPartySession(f.ctx, input, f.req),
    ).rejects.toThrow()
    expect(f.provider.deviceManager.createEphemeral).not.toHaveBeenCalled()
    expect(f.provider.requestManager.setAuthorized).not.toHaveBeenCalled()
    if (failure === 'missing' || failure === 'external')
      expect(f.nativeFetch).not.toHaveBeenCalled()
    jest.restoreAllMocks()
  }
})
