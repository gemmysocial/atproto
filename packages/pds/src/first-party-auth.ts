import type { IncomingMessage } from 'node:http'
import {
  AuthRequiredError,
  ForbiddenError,
  InvalidRequestError,
} from '@atproto/xrpc-server'
import type { OAuthConfig } from './config/config.js'
import type { AppContext } from './context.js'

type FirstPartyConfig = Pick<
  NonNullable<OAuthConfig['provider']>,
  'firstPartyClients' | 'firstPartyClientTemplates'
>

export type FirstPartySignInInput = {
  identifier: string
  password: string
  authFactorToken?: string
  requestUri: string
  locale?: string
}

/** Only operator-configured client IDs can use first-party authorization. */
export function isFirstPartyClient(clientId: string, config: FirstPartyConfig) {
  let url: URL
  try {
    url = new URL(clientId)
  } catch {
    return false
  }
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  )
    return false
  if (config.firstPartyClients?.includes(clientId)) return true

  return (
    config.firstPartyClientTemplates?.some((template) => {
      const marker = '{runId}'
      if (template.split(marker).length !== 2) return false
      const position = template.indexOf(marker)
      const hostEnd = template.indexOf('/', 'https://'.length)
      if (
        !template.startsWith('https://') ||
        hostEnd < 0 ||
        position < 8 ||
        position >= hostEnd
      )
        return false
      let parsed: URL
      try {
        parsed = new URL(template.replace(marker, '1'))
      } catch {
        return false
      }
      if (parsed.username || parsed.password || parsed.search || parsed.hash)
        return false
      const [prefix, suffix] = template.split(marker)
      if (!clientId.startsWith(prefix) || !clientId.endsWith(suffix))
        return false
      const runId = clientId.slice(
        prefix.length,
        clientId.length - suffix.length,
      )
      return /^[1-9][0-9]{0,19}$/.test(runId)
    }) ?? false
  )
}

/** Fresh PDS credentials authorize the owned confidential client without browser UI. */
export async function authorizeFirstPartySession(
  ctx: Pick<AppContext, 'cfg' | 'oauthProvider' | 'accountManager'>,
  input: FirstPartySignInInput,
  req: IncomingMessage,
) {
  const provider = ctx.oauthProvider
  const config = ctx.cfg.oauth.provider
  if (!provider || !config)
    throw new ForbiddenError('First-party sign-in is unavailable')
  if (req.headers.cookie || req.headers.authorization) {
    throw new InvalidRequestError('Fresh account credentials are required')
  }
  let pending: Awaited<
    ReturnType<typeof provider.requestManager.getAuthenticated>
  >
  try {
    pending = await provider.requestManager.getAuthenticated(input.requestUri)
  } catch {
    throw new InvalidRequestError('Invalid first-party authorization request')
  }
  if (!isFirstPartyClient(pending.clientId, config)) {
    throw new ForbiddenError('Client is not configured for first-party sign-in')
  }
  const client = await provider.clientManager.getClient(pending.clientId)
  if (
    client.metadata.token_endpoint_auth_method !== 'private_key_jwt' ||
    !pending.parameters.state
  ) {
    throw new InvalidRequestError(
      'A confidential client and state are required',
    )
  }
  const { user, appPassword, isSoftDeleted } =
    await ctx.accountManager.login(input)
  if (appPassword || isSoftDeleted) {
    throw new AuthRequiredError('A full, active account sign-in is required')
  }
  const { account, authorizedClients } =
    await provider.accountManager.getAccount(user.did)
  const hint = pending.parameters.login_hint
  if (
    !hint ||
    (hint !== account.did &&
      hint.toLowerCase() !== account.handle?.toLowerCase())
  )
    throw new AuthRequiredError(
      'Sign-in account does not match the authorization request',
    )

  const { deviceId, deviceMetadata } =
    await provider.deviceManager.createEphemeral(req)
  await provider.accountManager.upsertDeviceAccount(deviceId, account.did)
  await provider.requestManager.get(pending.requestUri, deviceId, client.id)
  const code = await provider.requestManager.setAuthorized(
    pending.requestUri,
    client,
    account,
    deviceId,
    deviceMetadata,
  )
  const previous = authorizedClients.get(client.id)
  await provider.accountManager.setAuthorizedClient(account, client, {
    authorizedScopes: [
      ...new Set([
        ...(previous?.authorizedScopes ?? []),
        ...(pending.parameters.scope?.split(' ') ?? []),
      ]),
    ],
  })
  return { code, state: pending.parameters.state, iss: provider.issuer }
}
