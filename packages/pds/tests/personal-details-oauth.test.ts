import { jest } from '@jest/globals'
import { type SeedClient, TestNetworkNoAppView } from '@atproto/dev-env'
import type { DidString } from '@atproto/syntax'
import { app } from '../src/lexicons/index.js'
import usersSeed from './seeds/users.js'

const clientId = 'https://staging-api.gems.xyz/auth/oauth-client-metadata.json'
const personalDetails = app.bsky.actor.defs.personalDetailsPref
const birthDate = '1990-01-01T00:00:00.000Z'

describe('first-party OAuth personal details', () => {
  let network: TestNetworkNoAppView
  let sc: SeedClient

  beforeAll(async () => {
    network = await TestNetworkNoAppView.create({
      pds: {
        firstPartyOAuthClients: [clientId],
        bskyAppViewDid: 'did:web:appview.test',
      },
    })
    sc = network.getSeedClient()
    await usersSeed(sc)
  }, 20_000)

  afterAll(async () => network?.close())

  beforeEach(async () => {
    await network.pds
      .getAgent()
      .app.bsky.actor.putPreferences(
        { preferences: [personalDetails.$build({ birthDate })] },
        { headers: sc.getHeaders(sc.dids.alice), encoding: 'application/json' },
      )
  })

  async function asOAuth(
    verifiedClientId: string | undefined,
    authenticateMethod: 'private_key_jwt' | 'none',
    run: (headers: { authorization: string }) => Promise<void>,
    includeRpcScopes = true,
  ) {
    const ctx = network.pds.ctx
    const verifier = ctx.authVerifier.oauthVerifier
    const provider = ctx.oauthProvider!
    const audience = `${ctx.bskyAppView!.did}#bsky_appview`
    const methods = [
      app.bsky.actor.getPreferences.$lxm,
      app.bsky.actor.putPreferences.$lxm,
    ]
    const scope = [
      'atproto',
      ...(includeRpcScopes
        ? methods.map(
            (method) => `rpc:${method}?aud=${encodeURIComponent(audience)}`,
          )
        : []),
    ].join(' ')

    // @NOTE Stub token verification only; permissions, handlers and storage stay real.
    using _verify = jest
      .spyOn(verifier, 'authenticateRequest')
      .mockResolvedValue({
        sub: sc.dids.alice as DidString,
        scope,
        client_id: verifiedClientId,
      } as Awaited<ReturnType<typeof verifier.authenticateRequest>>)
    using _metadata = jest
      .spyOn(provider.clientManager, 'getClient')
      .mockResolvedValue({
        id: verifiedClientId,
        metadata: { token_endpoint_auth_method: authenticateMethod },
      } as Awaited<ReturnType<typeof provider.clientManager.getClient>>)

    await run({ authorization: 'DPoP test-token' })
  }

  it('lets a configured confidential client read and update its own birthdate', async () => {
    await asOAuth(clientId, 'private_key_jwt', async (headers) => {
      const agent = network.pds.getAgent()
      const updated = personalDetails.$build({
        birthDate: '1991-02-03T00:00:00.000Z',
      })
      await agent.app.bsky.actor.putPreferences(
        { preferences: [updated] },
        { headers, encoding: 'application/json' },
      )
      const result = await agent.app.bsky.actor.getPreferences({}, { headers })
      expect(result.data.preferences).toContainEqual(updated)
      expect(result.data.preferences).toContainEqual(
        app.bsky.actor.defs.declaredAgePref.$build({
          isOverAge13: true,
          isOverAge16: true,
          isOverAge18: true,
        }),
      )
    })
  })

  it.each([
    ['https://other.example/client.json', 'private_key_jwt'],
    [clientId + '?spoof=1', 'private_key_jwt'],
    [clientId, 'none'],
    [undefined, 'private_key_jwt'],
  ] as const)(
    'keeps personal details private for %s using %s',
    async (id, method) => {
      await asOAuth(id, method, async (headers) => {
        const agent = network.pds.getAgent()
        const result = await agent.app.bsky.actor.getPreferences(
          {},
          { headers },
        )
        expect(result.data.preferences.some(personalDetails.$isTypeOf)).toBe(
          false,
        )
        await expect(
          agent.app.bsky.actor.putPreferences(
            {
              preferences: [
                personalDetails.$build({
                  birthDate: '1992-01-01T00:00:00.000Z',
                }),
              ],
            },
            { headers, encoding: 'application/json' },
          ),
        ).rejects.toThrow('Do not have authorization to set preferences')
      })
      const saved = await network.pds
        .getAgent()
        .app.bsky.actor.getPreferences(
          {},
          { headers: sc.getHeaders(sc.dids.alice) },
        )
      expect(saved.data.preferences).toContainEqual(
        personalDetails.$build({ birthDate }),
      )
    },
  )

  it('lets external clients update ordinary preferences without removing the birthdate', async () => {
    await asOAuth(
      'https://other.example/client.json',
      'private_key_jwt',
      async (headers) => {
        await network.pds
          .getAgent()
          .app.bsky.actor.putPreferences(
            { preferences: [] },
            { headers, encoding: 'application/json' },
          )
      },
    )
    const saved = await network.pds
      .getAgent()
      .app.bsky.actor.getPreferences(
        {},
        { headers: sc.getHeaders(sc.dids.alice) },
      )
    expect(saved.data.preferences).toContainEqual(
      personalDetails.$build({ birthDate }),
    )
  })

  it('still requires the RPC permission for a configured client', async () => {
    await asOAuth(
      clientId,
      'private_key_jwt',
      async (headers) => {
        await expect(
          network.pds
            .getAgent()
            .app.bsky.actor.putPreferences(
              { preferences: [personalDetails.$build({ birthDate })] },
              { headers, encoding: 'application/json' },
            ),
        ).rejects.toThrow()
      },
      false,
    )
  })
})
