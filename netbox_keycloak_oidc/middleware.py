import logging
import time
from urllib.parse import urlencode

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.views import redirect_to_login
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse
from django.utils.translation import gettext as _
from requests import HTTPError, RequestException
from social_core.exceptions import AuthConnectionError, AuthException
from social_django.utils import load_backend, load_strategy

from . import BACKEND_NAME
from .utils import (
    SESSION_ID_TOKEN,
    SESSION_LAST_CHECK,
    SESSION_REFRESH_TOKEN,
    SESSION_SUBJECT,
    extract_roles,
    get_setting,
)

logger = logging.getLogger('netbox_keycloak_oidc.session')


def get_backend(request):
    return load_backend(load_strategy(request), BACKEND_NAME, redirect_uri=None)


class SessionInvalid(Exception):
    pass


def validate_session(request):
    """
    Check with Keycloak that the SSO session behind this NetBox session is still alive.

    This uses the refresh token obtained at login: Keycloak rejects it once the SSO session has ended
    (logout, idle/max lifespan, session revoked by an admin) or the user has been disabled. The returned
    tokens are validated again and the required roles are re-checked, so revoking a role in Keycloak
    takes effect without the user logging in again.

    Raises SessionInvalid if the session must be terminated.
    """
    session = request.session
    backend = get_backend(request)
    try:
        data = backend.refresh_token(session[SESSION_REFRESH_TOKEN])
    except HTTPError as e:
        status = e.response.status_code if e.response is not None else None
        if status is not None and 400 <= status < 500:
            raise SessionInvalid(f'Keycloak rejected the refresh token (HTTP {status})') from e
        _unreachable(e)
        return
    except (AuthConnectionError, RequestException) as e:
        _unreachable(e)
        return
    except AuthException as e:
        raise SessionInvalid(f'Invalid token returned by Keycloak: {e}') from e

    if backend.id_token and session.get(SESSION_SUBJECT) not in (None, backend.id_token.get('sub')):
        raise SessionInvalid('Subject of the refreshed ID token does not match')

    required_roles = set(get_setting('required_roles'))
    if required_roles:
        try:
            roles = extract_roles(backend.decode_access_token(data['access_token']), backend.setting('KEY'))
        except (AuthException, KeyError) as e:
            raise SessionInvalid(f'Unable to verify the refreshed access token: {e}') from e
        roles |= extract_roles(backend.id_token or {}, backend.setting('KEY'))
        if not required_roles & roles:
            raise SessionInvalid('User no longer holds any of the required roles')

    session[SESSION_REFRESH_TOKEN] = data.get('refresh_token') or session[SESSION_REFRESH_TOKEN]
    if data.get('id_token'):
        session[SESSION_ID_TOKEN] = data['id_token']
    session[SESSION_LAST_CHECK] = time.time()


def _unreachable(error):
    if get_setting('session_check_fail_closed'):
        raise SessionInvalid(f'Keycloak is unreachable: {error}') from error
    logger.warning(f'Keycloak is unreachable, keeping session: {error}')


def get_end_session_url(request, id_token, redirect_url):
    """
    Return the Keycloak RP-initiated logout URL, or None if the realm does not provide one.
    """
    backend = get_backend(request)
    endpoint = backend.oidc_config().get('end_session_endpoint')
    if not endpoint:
        return None
    params = {
        'client_id': backend.setting('KEY'),
        'post_logout_redirect_uri': request.build_absolute_uri(redirect_url),
    }
    if id_token:
        params['id_token_hint'] = id_token
    return f'{endpoint}?{urlencode(params)}'


class KeycloakSessionMiddleware:
    """
    * Periodically re-validates sessions created through a Keycloak login (see validate_session()).
    * Ends the Keycloak SSO session as well when the user logs out of NetBox.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        session = getattr(request, 'session', None)
        if session is None or not request.user.is_authenticated or SESSION_REFRESH_TOKEN not in session:
            return self.get_response(request)

        if request.path == reverse('logout'):
            return self.logout(request)

        interval = get_setting('session_check_interval')
        if interval and time.time() - session.get(SESSION_LAST_CHECK, 0) >= interval:
            try:
                validate_session(request)
            except SessionInvalid as e:
                return self.terminate(request, str(e))

        return self.get_response(request)

    def process_exception(self, request, exception):
        """
        Send users back to the login page with an error message if a Keycloak login fails (e.g. a required
        role is missing or a token is invalid), instead of answering with a server error.
        """
        backend = getattr(exception, 'backend', None)
        if settings.DEBUG or not isinstance(exception, AuthException) or getattr(backend, 'name', None) != BACKEND_NAME:
            return None
        logger.warning(f'Keycloak login failed: {exception}')
        messages.error(request, _('Login via Keycloak failed: {error}').format(error=exception))
        return HttpResponseRedirect(settings.LOGIN_URL)

    def logout(self, request):
        id_token = request.session.get(SESSION_ID_TOKEN)
        response = self.get_response(request)
        if not get_setting('logout_from_keycloak') or not isinstance(response, HttpResponseRedirect):
            return response
        try:
            url = get_end_session_url(request, id_token, response['Location'])
        except Exception as e:
            logger.warning(f'Unable to determine the Keycloak logout URL: {e}')
            return response
        if url:
            response['Location'] = url
        return response

    def terminate(self, request, reason):
        logger.info(f'Terminating session of {request.user}: {reason}')
        logout(request)
        if request.path.startswith(reverse('api-root')):
            # Let the API respond as it would for an unauthenticated request
            return self.get_response(request)
        messages.warning(request, _('Your Keycloak session has ended. Please log in again.'))
        login_redirect = redirect_to_login(request.get_full_path())
        if getattr(request, 'htmx', False):
            response = HttpResponse()
            response['HX-Redirect'] = login_redirect['Location']
            return response
        return login_redirect
