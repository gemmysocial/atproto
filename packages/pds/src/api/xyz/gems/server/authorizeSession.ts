import { DAY, MINUTE } from '@atproto/common'
import { AuthRequiredError, Server } from '@atproto/xrpc-server'
import { OLD_PASSWORD_MAX_LENGTH } from '../../../../account-manager/helpers/scrypt.js'
import { AppContext } from '../../../../context.js'
import { authorizeFirstPartySession } from '../../../../first-party-auth.js'
import { xyz } from '../../../../lexicons/index.js'

export default function (server: Server, ctx: AppContext) {
  server.add(xyz.gems.server.authorizeSession, {
    // Match the existing native createSession account/IP login policy.
    rateLimit: [
      {
        durationMs: DAY,
        points: 300,
        calcKey: ({ input, req }) =>
          `${input.body.identifier.trim().toLowerCase()}-${req.ip}`,
      },
      {
        durationMs: 5 * MINUTE,
        points: 30,
        calcKey: ({ input, req }) =>
          `${input.body.identifier.trim().toLowerCase()}-${req.ip}`,
      },
    ],
    handler: async ({ input: { body }, req }) => {
      if (body.password.length > OLD_PASSWORD_MAX_LENGTH) {
        throw new AuthRequiredError(
          'Password too long. Consider resetting your password.',
        )
      }
      return {
        encoding: 'application/json',
        body: await authorizeFirstPartySession(ctx, body, req),
      }
    },
  })
}
