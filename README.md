# dotplan.online

## The un-social network.

- User-provided content tied to an email address.
- Text only, limited to 4kb.
- No retweets, shares, @s, likes, or boosting of any kind.
- Authenticity optionally verified by clients using public PGP keys.
- Accessed via public APIs.
- Open source.
- Self-hostable, discovery via domain SRV records.
- Single giant Perl script because PERL IS AWESOME!

## API

### Authentication

- `POST /users/{email}` - request new account
   - request data: `{"password":"whatever"}`
   - email with validation token will be sent
- `GET /users/{email}?token={token}` - validate new account
- `GET /users/{email}/token` - retrieve auth token
   - http basic auth
   - `?expires={date}` sets an explicit expiration, default is 300 seconds from creation
   - response data: `{"token":"whatever"}`
- `DELETE /users/{email}/token` - invalidate current auth token
   - http basic auth
- `GET /users/{email}/pwtoken` - get password change token
   - email with password change token will be sent
- `PUT /users/{email}` - update password
   - request data: `{"password":"whatever","pwtoken":"whatever"}`
   - token expires 600 seconds from creation

### Plans

- `PUT /plan/{email}` - update a plan
   - request data: `{"plan":"whatever","signature":"whatever"}`
- `GET /plan/{email}` - retrieve a plan
   - `text/plain` by default - raw plan content
   - `?format=html` or `Accept: text/html` - plan content with html entity encoding for special characters
   - `?format=json` or `Accept: application/json` - response data: `{"plan":"whatever","signature":"whatever"}`
   - `404` if no plan found
- `POST /verify/{email}` - verify PGP signature of a plan
   - request data: `{"pgpkey":"public key"}`
   - response data: `{"plan":"whatever","verified":true}` or `{"verified":false}`
   - 404 if no plan found
- `POST /multi` - retrieve multiple plans
   - request data: `{"plans":["user1@email.dom","user2@email.dom"],"pgpkeys":{"user1@email.dom":"public key"}}`
   - response data: `{"user1@email.dom":{"plan":"whatever","verified":true},"user2@email.dom":{"plan":"whatever","signature":"whatever"}}`
   - emails with no plan found excluded from response
