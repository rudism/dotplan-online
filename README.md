# Dotplan

## The un-social network.

- User-provided content tied to an email address.
- Text only.
- No re-tweets, shares, @s, likes, or boosting of any kind.
- Authenticity optionally verified by clients using OpenBSD signify/[Minisign](https://jedisct1.github.io/minisign/).
- Accessed via public APIs.
- Open source.
- Self-hostable, discovery via domain SRV records.

## API

Any Dotplan implementation should expose at least the following endpoint and behavior:

- `GET /plan/{email}` - retrieve a plan
   - `Accept: text/plain` request header - return raw plan content
   - `Accept: application/json` request header - return json plan details:
      - `plan` - raw plan content
      - `timestamp` - when this plan was created
      - `signature` - optional signature if this plan was signed
   - `Last-Modified` response header should indicate when the plan was created
   - `X-Dotplan-Pubkey: {base64 signify pubkey}` request header - perform signature verification
      - append `X-Dotplan-Verified: true` response header if verification succeeded
      - `403` if verification failed or is not supported by the server
      - client-side signature verification using the json response should be favored since the server may not be trusted
   - `404` if no plan found
   - `301` redirect if domain SRV record indicates plan is on a different dotplan provider
      - this is optional for servers to act as relays, client-side SRV lookups should be favored since the server may not be trusted

### Authentication

The reference dotplan implementation also exposes these endpoints for account management and authentication. Other implementations may differ and offer other authentication mechanisms (OAuth2 for example, or supporting the creation and invalidation of multiple authentication tokens).

- `POST /users/{email}` - request new account
   - request json data:
      - `password` - the password for the new account
   - an email with a validation link will be sent
- `PUT /users/{email}` - validate new account
   - request json data:
      - `token` - the validation token from the email
- `GET /token` - retrieve auth token
   - http basic auth
   - `?expires={minutes}` sets an explicit expiration, default is 5 minutes from creation
   - response json data:
      - `token` - the authentication token
- `DELETE /token` - invalidate current auth token
   - http basic auth
- `GET /users/{email}/pwchange` - get password change token
   - an email with a password change token will be sent
   - token expires 600 seconds from creation
- `PUT /users/{email}/pwchange` - update password
   - request json data:
      - `password` - the new password
      - `token` - the password change token from the email

### Updating a Plan

The reference dotplan implementation exposes this endpoint to update a plan using a given authentication token. Other implementations may differ and offer other mechanisms to update a plan (by email or text message for example, or integration with other services).

- `PUT /plan/{email}` - update a plan
   - request json data:
      - `plan` - optional new plan content
      - `signature` - optional ascii encoded PGP signature
      - `auth` - the authentication token
   - omitting `plan` from the payload will delete the existing plan
