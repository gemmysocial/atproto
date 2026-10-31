---
'@atproto/oauth-provider': patch
'@atproto/pds': patch
---

Allow operator-configured confidential first-party clients to authorize a native account sign-in without a browser or consent screen. Verify fresh PDS credentials against an authenticated PAR, bind the account and device, and return only the existing one-use OAuth authorization response.
