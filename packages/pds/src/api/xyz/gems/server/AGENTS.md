Keep first-party authorization bound to a signed confidential-client PAR and
the configured loopback native authenticator, including its MFA policy. Revoke
temporary native refresh credentials inside the PDS before issuing the OAuth
code; upstream credentials must never leave this endpoint.
