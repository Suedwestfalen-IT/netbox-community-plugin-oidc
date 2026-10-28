# netbox-keycloak-oidc

A NetBox (Community Edition) plugin for logging in via **Keycloak** using **OpenID Connect**.

It builds on the python-social-auth OIDC support that ships with NetBox and adds:

* **A `keycloak-oidc` authentication backend.** It uses the authorization code flow with **PKCE (S256)**
  and fully validates the ID token: signature via the realm JWKS, issuer, audience, authorized party,
  expiry, issue time, nonce and `at_hash`. The Keycloak access token is verified too, and realm roles,
  client roles and groups are read from it.
* **Access control.** Only users holding one of the `required_roles` may log in. Users without one never
  get a NetBox account.
* **Role mapping.** Keycloak roles or groups are mapped to NetBox groups and to superuser status.
* **Session validation.** Every NetBox session created by a Keycloak login is checked against Keycloak at a
  fixed interval (by redeeming the refresh token). When the SSO session ends (logout elsewhere, idle or max
  lifespan reached, session revoked by an admin), the user is disabled, or a required role is revoked,
  the user is logged out of NetBox.
* **Single logout.** Logging out of NetBox also ends the Keycloak SSO session (RP-initiated logout).
* **Diagnostics.** A status page (superusers only) and a `manage.py keycloak_oidc_check` command check the
  configuration, OIDC discovery, issuer, signing keys, PKCE support, the logout endpoint and the client
  credentials against the live Keycloak realm.

Requires NetBox 4.4 or later and Keycloak 18 or later (URLs without the `/auth` prefix; older versions work
if you include `/auth` in the endpoint).

## Keycloak setup

1. In your realm, create a client (*Clients → Create client*):
   * Client type: **OpenID Connect**, Client ID e.g. `netbox`
   * **Client authentication: On** (confidential client), **Standard flow: On**. All other flows can be off.
   * Valid redirect URIs: `https://netbox.example.com/oauth/complete/keycloak-oidc/`
   * Valid post logout redirect URIs: `https://netbox.example.com/*` (or `+`)
2. Copy the client secret from *Credentials*.
3. Create the roles you want to use, e.g. client roles `netbox-user` and `netbox-admin` (*Clients → netbox →
   Roles*), and assign them to users or groups. To use group memberships instead, add a *Group Membership*
   mapper named `groups` to the client's dedicated scope (with *Add to access token* enabled).

The plugin reads roles from the access token, which Keycloak populates by default (`realm_access`,
`resource_access`). No additional mappers are required for roles.

## Installation

Install the package into the NetBox virtual environment:

```bash
source /opt/netbox/venv/bin/activate
pip install git+https://github.com/Suedwestfalen-IT/netbox-community-plugin-oidc.git
```

To keep the plugin installed across NetBox upgrades, add it to `/opt/netbox/local_requirements.txt`:

```
netbox-keycloak-oidc @ git+https://github.com/Suedwestfalen-IT/netbox-community-plugin-oidc.git
```

Then configure NetBox in `configuration.py`:

```python
PLUGINS = ['netbox_keycloak_oidc']

PLUGINS_CONFIG = {
    'netbox_keycloak_oidc': {
        'required_roles': ['netbox-user', 'netbox-admin'],
        'superuser_roles': ['netbox-admin'],
        'group_mapping': {
            'netbox-user': ['Readers'],
        },
    },
}

REMOTE_AUTH_BACKEND = 'netbox_keycloak_oidc.backends.KeycloakOIDC'

SOCIAL_AUTH_KEYCLOAK_OIDC_OIDC_ENDPOINT = 'https://sso.example.com/realms/<realm>'
SOCIAL_AUTH_KEYCLOAK_OIDC_KEY = 'netbox'
SOCIAL_AUTH_KEYCLOAK_OIDC_SECRET = '<client secret>'

# Optional: hide the local username/password form and only offer Keycloak
# LOGIN_FORM_HIDDEN = True
```

Local NetBox accounts (e.g. an emergency admin) keep working through the username/password form, because
NetBox always enables its local authentication backend in addition to `REMOTE_AUTH_BACKEND`.

Restart NetBox and run the check:

```bash
cd /opt/netbox/netbox
python manage.py keycloak_oidc_check
```

```
[OK     ] Authentication backend: netbox_keycloak_oidc.backends.KeycloakOIDC
[OK     ] Client configuration: Client ID: netbox
[OK     ] OIDC discovery: https://sso.example.com/realms/netbox/.well-known/openid-configuration
[OK     ] Issuer: https://sso.example.com/realms/netbox
[OK     ] Signing keys (JWKS): 1 key(s) for RS256
[OK     ] PKCE: S256
[OK     ] Logout endpoint: https://sso.example.com/realms/netbox/protocol/openid-connect/logout
[OK     ] Client credentials: Accepted by Keycloak
[OK     ] Redirect URI: Must be allowed in the Keycloak client: /oauth/complete/keycloak-oidc/
```

The same checks are available in the UI under *Plugins → Keycloak OIDC Status* (superusers only), which
also shows the full redirect URI.

## Plugin settings

| Setting | Default | Description |
|---|---|---|
| `button_label` | `Keycloak` | Label of the login button (overridden by `SOCIAL_AUTH_BACKEND_ATTRS`) |
| `role_sources` | `['realm', 'client', 'groups']` | Where roles are read from: realm roles, roles of this client, group memberships (`/parent/child` matches both the full path and `child`) |
| `required_roles` | `[]` | A user needs at least one of these roles to log in. Empty: every user of the realm may log in |
| `superuser_roles` | `[]` | Users holding one of these roles become superusers; all others lose superuser status. Empty: superuser status is not managed |
| `group_mapping` | `{}` | Keycloak role to NetBox group(s), e.g. `{'netbox-admin': ['Admins', 'Operators']}` |
| `auto_create_groups` | `False` | Create mapped NetBox groups that do not exist yet. Otherwise they are skipped and an error is logged |
| `remove_unmapped_groups` | `True` | Remove a user from mapped groups once the corresponding role is gone. Groups not in the mapping are never touched |
| `session_check_interval` | `300` | Seconds between session validations against Keycloak. `0` disables the check |
| `session_check_fail_closed` | `False` | Log users out if Keycloak cannot be reached during validation (otherwise a warning is logged and the session kept) |
| `logout_from_keycloak` | `True` | End the Keycloak SSO session when the user logs out of NetBox |

Roles and groups are synchronized at every login. Superuser status and groups mapped through this plugin
should therefore be managed in Keycloak, not in NetBox.

The backend accepts all standard python-social-auth OIDC settings with the `SOCIAL_AUTH_KEYCLOAK_OIDC_`
prefix, e.g. `..._USE_PKCE`, `..._SCOPE`, `..._ID_KEY` or `..._USERNAME_KEY` (default: `preferred_username`).

## How login is checked

| Step | Check |
|---|---|
| Login start | `state`, `nonce` and a PKCE code challenge are generated and kept in the session |
| Callback | `state` must match. The code is redeemed with the client secret and PKCE verifier |
| ID token | RS256 signature against the realm JWKS, `iss` = realm, `aud` contains the client, `azp` = client, `exp`, `iat` (max. 10 minutes old), `nonce` (single use), `at_hash` |
| Access token | Signature, `iss`, `exp`, `azp` = client. Roles are only taken from verified tokens and the userinfo endpoint |
| Userinfo | `sub` must equal the ID token's `sub` |
| Authorization | `required_roles` are checked *before* a NetBox user is looked up or created |
| Session | Every `session_check_interval` seconds the refresh token is redeemed. Rejection, a different `sub` or a missing required role ends the NetBox session |
| Logout | The NetBox session is flushed and the browser is sent to Keycloak's `end_session_endpoint` with `id_token_hint` |

The plugin installs its pipeline steps for the `keycloak-oidc` backend only. If you define
`SOCIAL_AUTH_KEYCLOAK_OIDC_PIPELINE` yourself, include `netbox_keycloak_oidc.pipeline.check_access` (after
`social_uid`), `netbox_keycloak_oidc.pipeline.sync_roles` and `netbox_keycloak_oidc.pipeline.remember_tokens`.

Notes on session validation:

* Users who are idle in NetBox for longer than Keycloak's *SSO Session Idle* timeout (30 minutes by default)
  must log in again, because their refresh token has expired.
* If *Revoke Refresh Token* is enabled in the realm, concurrent requests of the same session can race during
  validation. Keep it disabled (the default) or set a *Refresh Token Max Reuse* above 0.
* API requests authenticated by NetBox API tokens are not affected. Only browser sessions are checked.

## Development

The tests run inside NetBox's test runner against an in-process imitation of a Keycloak realm (no network
access needed). They require a NetBox checkout with PostgreSQL and Redis available:

```bash
pip install -e /path/to/netbox-community-plugin-oidc
cd /path/to/netbox/netbox
NETBOX_CONFIGURATION=testing.configuration PYTHONPATH=/path/to/netbox-community-plugin-oidc \
    python manage.py test netbox_keycloak_oidc
```

Lint with `ruff check`.
