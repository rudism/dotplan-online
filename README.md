# dotplan.online

## The un-social network.

- User-provided content tied to an email address.
- Text only, limited to 4kb.
- No retweets, shares, @s, likes, or boosting of any kind.
- Authenticity verified by public PGP keys.
- Accessed via public APIs.
- Self-hostable, discovery via SRV records.

## API

- `POST /users` to register an email address.
   - Request data: `{"email":"whatever","password":"whatever"}`
   - Will require validation. Email with token link will be sent.
- `GET /users/{email}?token={token}` to validate an email.
- Token-based authentication.
   - `GET /users/{email}/token` with basic auth validation to get a token.
   - `DELETE /users/{email}/token` to manually invalidate any token.
- `PUT /plan/{email}` to update a .plan
   - Request data: `{"plan":"whatever","signature":"whatever"}`
   - Signature is optional PGP digital signature for the plan.
- `GET /plan/{email}` to retrieve a .plan without verification
   - Plain text by default, or based on `accept` header, or force:
     - `?format=html` will html-escape special characters.
     - `?format=json` response data: `{"plan":"whatever","signature":"whatever"}`
- `POST /verify/{email}` to retrieve and verify the signature of a .plan
   - Request data: `{"pgpkey":"public key"}`
   - Response data: `{"plan":"whatever","verified":(true|false)}`
