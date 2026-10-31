import type { IncomingMessage } from 'node:http'
import { expect, it, jest } from '@jest/globals'
import { DeviceManager } from '../../oauth/oauth-provider/dist/device/device-manager.js'
import { generateRequestId } from '../../oauth/oauth-provider/dist/request/request-id.js'
import { RequestManager } from '../../oauth/oauth-provider/dist/request/request-manager.js'
import { encodeRequestUri } from '../../oauth/oauth-provider/dist/request/request-uri.js'

it('requires signed confidential PAR and preserves the provider expiry/replay checks', async () => {
  const uri = encodeRequestUri(await generateRequestId())
  for (const failure of [
    'unsigned',
    'public',
    'expired',
    'replayed',
    'valid',
  ]) {
    const data = {
      clientAuth:
        failure === 'unsigned'
          ? null
          : { method: failure === 'public' ? 'none' : 'private_key_jwt' },
      clientId: 'https://staging-api.gems.xyz/auth/oauth-client-metadata.json',
      parameters: {
        redirect_uri: 'https://staging-api.gems.xyz/auth/oauth/callback',
      },
      expiresAt: new Date(
        Date.now() + (failure === 'expired' ? -60000 : 60000),
      ),
      did: failure === 'replayed' ? 'did:plc:alice' : null,
      code: null,
      deviceId: null,
    }
    const store = {
      readRequest: jest.fn(async () => data),
      updateRequest: jest.fn(async () => {}),
      deleteRequest: jest.fn(async () => {}),
    }
    const manager = new RequestManager(
      store as never,
      undefined as never,
      undefined as never,
      undefined as never,
      {},
    )
    if (failure === 'valid')
      expect((await manager.getAuthenticated(uri)).clientId).toBe(data.clientId)
    else await expect(manager.getAuthenticated(uri)).rejects.toThrow()
    if (['expired', 'replayed'].includes(failure))
      expect(store.deleteRequest).toHaveBeenCalled()
  }
})
it('rejects malformed request URIs before reading provider storage', async () => {
  const store = { readRequest: jest.fn() }
  const manager = new RequestManager(
    store as never,
    undefined as never,
    undefined as never,
    undefined as never,
    {},
  )
  await expect(
    manager.getAuthenticated('https://evil.example'),
  ).rejects.toThrow()
  expect(store.readRequest).not.toHaveBeenCalled()
})
it('creates a native device without a browser cookie or recoverable browser-session secret', async () => {
  const store = {
    createDevice: jest.fn(async (_id: unknown, _data: unknown) => {}),
  }
  const manager = new DeviceManager(store as never)
  const req = {
    headers: { 'user-agent': 'Gems Native' },
    socket: { remoteAddress: '127.0.0.1', remotePort: 50000 },
  } as IncomingMessage
  const result = await manager.createEphemeral(req)
  expect(Object.keys(result).sort()).toEqual(['deviceId', 'deviceMetadata'])
  expect(store.createDevice).toHaveBeenCalledTimes(1)
  expect(result.deviceMetadata.ipAddress).toBe('127.0.0.1')
})
