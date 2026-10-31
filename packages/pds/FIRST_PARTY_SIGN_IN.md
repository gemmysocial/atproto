# Native first-party sign-in

`xyz.gems.server.authorizeSession` lets an operator's own app use its native
username/password form while retaining the provider's confidential OAuth,
PKCE, DPoP, encrypted broker sessions and upstream revocation. External clients
continue to use the existing browser authorization and consent flow.

The operator must explicitly configure the complete first-party client IDs:

```
PDS_OAUTH_FIRST_PARTY_CLIENTS=https://staging-api.gems.xyz/auth/oauth-client-metadata.json
PDS_OAUTH_FIRST_PARTY_CLIENT_TEMPLATES=https://api-preview-q{runId}.gems.xyz/auth/oauth-client-metadata.json
```

Both lists default to empty. Templates are optional and allow one numeric CI run
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
login limits. It creates a provider device without browser cookies, associates
it with the authenticated account, and returns only `{code, state, iss}`. The
broker verifies the app transaction verifier and OAuth state/issuer, completes
the SDK callback and issues its existing per-device Gems session.

Deploy this PDS revision and configure the client IDs before releasing the app
revision that calls this procedure. The app must not silently fall back to a
browser for a failed first-party native sign-in. The PDS image publishing
workflow in this fork currently has an upstream-repository-only condition;
therefore the actual Gems deployment path must be identified before rollout.
