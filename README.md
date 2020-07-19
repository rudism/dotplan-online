# dotplan.online

## The un-social network.

- User-provided content tied to an email address.
- Text only, limited to 4kb.
- No retweets, shares, @s, likes, or boosting of any kind.
- Authenticity optionally verified by clients using public PGP keys.
- Accessed via public APIs.
- Open source.
- Self-hostable, discovery via domain SRV records.

## API

Any dotplan implementation should expose at least the following two endpoints:

- `GET /plan/{email}` - retrieve a plan
   - `text/plain` by default - raw plan content
   - `?format=html` or `Accept: text/html` - plan content with html entity encoding for special characters
   - `?format=json` or `Accept: application/json`:
      - `plan` - raw plan content
      - `signature` - ascii armored PGP signature if this plan was signed
      - `timestamp` - when this plan was created
   - `404` if no plan found
   - `301` redirect if domain SRV record indicates plan is on a different dotplan provider
      - This is optional for servers to act as relays, in practice the client should look up the SRV record itself
- `POST /verify/{email}` - verify PGP signature of a plan
   - request json data:
      - `pubkey` - ascii armored public PGP key to verify the signature with
   - response json data:
      - `verified` - `1` or `0` depending on whether verification of the plan signature was successful
      - normal plan details included if `verified=1`
   - `403` if server-side verification is not supported
   - `404` if no plan found
   - `308` redirect if domain SRV record indicates plan is on a different dotplan provider.
      - This is optional for servers to act as relays, in practice the client should look up the SRV record itself.

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
