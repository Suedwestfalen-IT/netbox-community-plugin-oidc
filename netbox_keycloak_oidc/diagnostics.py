"""
Connectivity and configuration checks against the configured Keycloak realm.

Used by the status page and the `keycloak_oidc_check` management command.
"""
from dataclasses import dataclass

import jwt
from django.conf import settings
from django.shortcuts import resolve_url
from django.urls import reverse
from requests import HTTPError, RequestException
from social_core.exceptions import AuthException
from social_django.utils import load_backend, load_strategy

from . import BACKEND_NAME
from .utils import get_setting

BACKEND_PATH = 'netbox_keycloak_oidc.backends.KeycloakOIDC'

OK = 'ok'
WARNING = 'warning'
FAILED = 'failed'


@dataclass
class Result:
    name: str
    status: str
    detail: str = ''


def get_redirect_uri(request=None):
    path = reverse('social:complete', args=[BACKEND_NAME])
    return request.build_absolute_uri(path) if request is not None else path


def run_diagnostics(request=None):
    results = []

    def add(name, status, detail=''):
        results.append(Result(name, status, detail))
        return status == OK

    # Static configuration
    if BACKEND_PATH in settings.AUTHENTICATION_BACKENDS:
        add('Authentication backend', OK, BACKEND_PATH)
    else:
        add('Authentication backend', FAILED, f'Add {BACKEND_PATH} to REMOTE_AUTH_BACKEND')
    missing = [
        f'SOCIAL_AUTH_KEYCLOAK_OIDC_{name}' for name in ('OIDC_ENDPOINT', 'KEY', 'SECRET')
        if not getattr(settings, f'SOCIAL_AUTH_KEYCLOAK_OIDC_{name}', None)
    ]
    if missing:
        add('Client configuration', FAILED, f'Missing: {", ".join(missing)}')
        return results
    add('Client configuration', OK, f'Client ID: {settings.SOCIAL_AUTH_KEYCLOAK_OIDC_KEY}')

    backend = load_backend(load_strategy(request), BACKEND_NAME, redirect_uri=get_redirect_uri(request))
    endpoint = backend.oidc_endpoint()

    # Discovery document (fetched directly to bypass the backend's cache)
    discovery_url = f'{endpoint}/.well-known/openid-configuration'
    try:
        config = backend.get_json(discovery_url)
    except (AuthException, RequestException, ValueError) as e:
        add('OIDC discovery', FAILED, f'{discovery_url}: {e}')
        return results
    add('OIDC discovery', OK, discovery_url)

    issuer = config.get('issuer')
    if issuer == endpoint:
        add('Issuer', OK, issuer)
    else:
        add('Issuer', FAILED, f'Discovery reports issuer {issuer!r}, expected {endpoint!r}')

    # Signing keys
    try:
        keys = backend.get_json(config['jwks_uri'])['keys']
        algorithms = backend.setting('JWT_ALGORITHMS', backend.JWT_ALGORITHMS)
        signing_keys = [k for k in keys if k.get('use', 'sig') == 'sig' and k.get('alg', algorithms[0]) in algorithms]
        if signing_keys:
            add('Signing keys (JWKS)', OK, f'{len(signing_keys)} key(s) for {", ".join(algorithms)}')
        else:
            add('Signing keys (JWKS)', FAILED, f'No signing key for {", ".join(algorithms)}')
    except (AuthException, RequestException, ValueError, KeyError) as e:
        add('Signing keys (JWKS)', FAILED, str(e))

    # PKCE
    use_pkce = backend.setting('USE_PKCE', backend.DEFAULT_USE_PKCE)
    if not use_pkce:
        add('PKCE', WARNING, 'Disabled')
    elif 'S256' in config.get('code_challenge_methods_supported', []):
        add('PKCE', OK, 'S256')
    else:
        add('PKCE', FAILED, 'Realm does not advertise S256 code challenges')

    # RP-initiated logout
    if config.get('end_session_endpoint'):
        add('Logout endpoint', OK, config['end_session_endpoint'])
    else:
        add('Logout endpoint', WARNING, 'No end_session_endpoint; Keycloak sessions are not ended on logout')

    # Client credentials: redeem a bogus authorization code. With valid credentials Keycloak answers
    # "invalid_grant" (the code is unknown); wrong credentials yield "invalid_client".
    try:
        backend.request(
            config['token_endpoint'],
            method='POST',
            data={
                'grant_type': 'authorization_code',
                'code': 'netbox-keycloak-oidc-diagnostics',
                'redirect_uri': backend.get_redirect_uri(),
                **({} if backend.use_basic_auth() else {'client_id': backend.setting('KEY'),
                                                        'client_secret': backend.setting('SECRET')}),
            },
            auth=(backend.setting('KEY'), backend.setting('SECRET')) if backend.use_basic_auth() else None,
        )
        add('Client credentials', WARNING, 'Unexpected success redeeming an invalid code')
    except HTTPError as e:
        try:
            error = e.response.json().get('error')
        except ValueError:
            error = None
        if error == 'invalid_grant':
            add('Client credentials', OK, 'Accepted by Keycloak')
        elif error in ('invalid_client', 'unauthorized_client'):
            add('Client credentials', FAILED, f'{error}: check client ID/secret and that the client is confidential '
                                              f'with "Standard flow" enabled')
        else:
            add('Client credentials', WARNING, f'HTTP {e.response.status_code}: {error or e.response.text[:200]}')
    except (AuthException, RequestException, KeyError) as e:
        add('Client credentials', FAILED, str(e))

    add('Redirect URI', OK, f'Must be allowed in the Keycloak client: {get_redirect_uri(request)}')
    if config.get('end_session_endpoint') and get_setting('logout_from_keycloak'):
        logout_url = resolve_url(settings.LOGOUT_REDIRECT_URL)
        if request is not None:
            logout_url = request.build_absolute_uri(logout_url)
        add('Post logout redirect URI', OK, f'Must be allowed in the Keycloak client: {logout_url}')

    if get_setting('scim_enabled'):
        run_scim_diagnostics(add)

    return results


def run_scim_diagnostics(add):
    from .scim import ScimClient

    client = ScimClient()
    try:
        token = client.token
    except HTTPError as e:
        add('SCIM token', FAILED, f'{client.client_id}: HTTP {e.response.status_code} {e.response.text[:200]} '
                                  f'(the client needs "Service accounts roles" enabled)')
        return
    except (AuthException, RequestException, KeyError, ValueError) as e:
        add('SCIM token', FAILED, f'{client.client_id}: {e}')
        return
    add('SCIM token', OK, f'Client credentials grant for {client.client_id}')

    claims = jwt.decode(token, options={'verify_signature': False})
    audience = claims.get('aud') or []
    if client.base_url not in ([audience] if isinstance(audience, str) else audience):
        add('SCIM audience', FAILED, f'Access token lacks the audience {client.base_url}: add an Audience mapper '
                                     f'(Included Custom Audience) to the client')
        return
    add('SCIM audience', OK, client.base_url)

    for resource, role in (('Users', 'query-users / view-users'), ('Groups', 'query-groups')):
        try:
            total = client.get(resource, {'count': 1}).get('totalResults')
            add(f'SCIM {resource}', OK, f'{total} {resource.lower()} readable')
        except HTTPError as e:
            status = e.response.status_code
            hint = {
                401: e.response.text[:200],
                403: f'the service account needs the realm-management role(s) {role}',
                404: 'SCIM API not found: enable it for the realm (Realm settings > General > SCIM API); '
                     'requires Keycloak 26.8 or later',
            }.get(status, e.response.text[:200])
            add(f'SCIM {resource}', FAILED, f'HTTP {status}: {hint}')
        except (AuthException, RequestException, ValueError) as e:
            add(f'SCIM {resource}', FAILED, str(e))
