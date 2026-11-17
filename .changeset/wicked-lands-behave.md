---
'@atproto/pds': patch
---

Allow configured confidential first-party OAuth clients to read and update their
own birthdate preferences while retaining RPC scope checks and private preference
restrictions for other OAuth clients and app passwords.

Preserve a freshly issued native MFA challenge when Gatekeeper cannot deliver
its email, without authorizing a session until the code has been verified.
