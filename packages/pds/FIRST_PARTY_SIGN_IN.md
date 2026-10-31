# Native first-party sign-in

`xyz.gems.server.authorizeSession` lets an operator's own app use its native
username/password form while retaining the provider's confidential OAuth,
PKCE, DPoP, encrypted broker sessions and upstream revocation. External clients
continue to use the existing browser authorization and consent flow.

The operator must explicitly configure the complete first-party client IDs:

```
PDS_OAUTH_NATIVE_AUTH_ORIGIN=http://127.0.0.1:8080
PDS_OAUTH_FIRST_PARTY_CLIENTS=https://staging-api.gems.xyz/auth/oauth-client-metadata.json
PDS_OAUTH_FIRST_PARTY_CLIENT_TEMPLATES=https://api-preview-q{runId}.gems.xyz/auth/oauth-client-metadata.json
```

The native authentication origin is required and restricted to an HTTP loopback address.
It points at the existing Gatekeeper native sign-in endpoint, preserving its
email two-factor checks. The resulting temporary native refresh token is
verified against the PDS signing key and revoked inside the PDS before issuing
an OAuth code. Neither native token is returned to the app or broker.

Both client lists default to empty. Templates are optional and allow one numeric CI run
ID in the hostname, with the remainder of the client ID matched exactly. Do not
configure a template for a domain where untrusted users control deployments.
The first-party privilege requires a signed `private_key_jwt` PAR from that
configured client, rather than matching a claimed client ID alone.

The app starts a verifier-bound broker transaction. The broker resolves the
account and verifies that both its PDS and OAuth issuer are `https://gems.xyz`.
It creates the normal confidential PAR and returns its `request_uri` to the app.
The app sends its identifier, password and request URI directly to this PDS
procedure with browser credentials omitted and redirects forbidden. Passwords
never pass through the Gems broker or enter persisted app state.

The procedure rejects ambient cookies/authorization, public or untrusted clients,
expired or consumed requests, app passwords, inactive accounts and mismatched
account identities. It uses the PDS's existing native credential verifier and
login limits, then requires the configured native authenticator to complete
its existing MFA policy. It creates a provider device without browser cookies, associates
it with the authenticated account, and returns only `{code, state, iss}`. The
broker verifies the app transaction verifier and OAuth state/issuer, completes
the SDK callback and issues its existing per-device Gems session.

Deploy this PDS revision and configure the client IDs before releasing the app
revision that calls this procedure. The app must not silently fall back to a
browser for a failed first-party native sign-in. The Gems deployment runs on droplet 570940651 at 206.189.187.248, using
`/pds/compose.yaml`. This patch is based on the exact running upstream revision
`ac0c9f15392f6f0298d71dc52aa88c05036150be`; a narrow image overlay must retain
the custom `gems/pds:spaces-alpha-20261022` base. The pre-change backup is
`/var/backups/gems-pds/20261031T104919Z` with a verified off-server copy at
`/Users/joefitter/Dev/gems/pds-backups/20261031T104919Z`. All 29 SQLite databases
passed restore integrity checks, and archive checksums match both copies.

Build the verified runtime overlay from the repository root after compiling the
PDS and provider packages:

```sh
docker build -f packages/pds/Dockerfile.gems-native-first-party -t gems/pds:native-first-party .
```

Its base-file guards reject a different installed JavaScript revision before
copying the native sign-in changes. No database schema or migration is changed.
