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
- `GET /token` - retrieve auth token
   - http basic auth
   - `?expires={minutes}` sets an explicit expiration, default is 5 minutes from creation
   - response data: `{"token":"whatever"}`
- `DELETE /token` - invalidate current auth token
   - http basic auth
- `GET /users/{email}/pwtoken` - get password change token
   - email with password change token will be sent
- `PUT /users/{email}` - update password
   - request data: `{"password":"whatever","pwtoken":"whatever"}`
   - token expires 600 seconds from creation

### Plans

- `PUT /plan/{email}` - update a plan
   - request data: `{"plan":"whatever","signature":"base64 encoded signature","auth":"token"}`
   - omitting `plan` from the payload will delete the existing plan
- `GET /plan/{email}` - retrieve a plan
   - `text/plain` by default - raw plan content
   - `?format=html` or `Accept: text/html` - plan content with html entity encoding for special characters
   - `?format=json` or `Accept: application/json` - response data: `{"plan":"whatever","signature":"base64 encoded signature"}`
   - `404` if no plan found
   - `301` redirect if plan is on a different provider
- `POST /verify/{email}` - verify PGP signature of a plan
   - request data: `{"pgpkey":"ascii public key"}`
   - response data: `{"plan":"whatever","verified":1}` or `{"verified":0}`
   - `404` if no plan found
   - `308` redirect if plan is on a different provider
