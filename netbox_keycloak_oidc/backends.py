import logging

import jwt
from django.conf import settings
from social_core.backends.oauth import BaseOAuth2PKCE
from social_core.backends.open_id_connect import OpenIdConnectAuth
from social_core.exceptions import AuthTokenError

from . import BACKEND_NAME
from .utils import extract_groups, extract_roles

logger = logging.getLogger('netbox_keycloak_oidc.backend')


# BaseOAuth2PKCE is listed explicitly for social-auth-core < 5 (NetBox < 4.7), whose OIDC backend lacks PKCE
class KeycloakOIDC(OpenIdConnectAuth, BaseOAuth2PKCE):
    """
    OpenID Connect backend for Keycloak.

    Builds on python-social-auth's generic OIDC backend, which discovers all endpoints from the realm's
    `.well-known/openid-configuration` and fully validates the ID token (signature via JWKS, issuer,
    audience, authorized party, expiry, issue time, nonce and at_hash). On top of that this backend:

      * enables PKCE (S256) by default,
      * verifies the Keycloak access token (a signed JWT) and reads realm roles, client roles and
        groups from it, so that role mappers need not be added to the ID token or userinfo.

    Configuration (configuration.py):

        REMOTE_AUTH_BACKEND = 'netbox_keycloak_oidc.backends.KeycloakOIDC'
        SOCIAL_AUTH_KEYCLOAK_OIDC_OIDC_ENDPOINT = 'https://sso.example.com/realms/<realm>'
        SOCIAL_AUTH_KEYCLOAK_OIDC_KEY = '<client id>'
        SOCIAL_AUTH_KEYCLOAK_OIDC_SECRET = '<client secret>'
    """

    name = BACKEND_NAME
    DEFAULT_USE_PKCE = True
    # RFC 7636 spells the method "S256"; social-auth-core < 5 defaults to "s256", which Keycloak rejects
    PKCE_DEFAULT_CODE_CHALLENGE_METHOD = 'S256'

    def setting(self, name, default=None):
        value = super().setting(name, default)
        if name == 'PROXIES' and not value:
            # Fall back to NetBox's HTTP_PROXIES, which python-social-auth does not use on its own
            value = getattr(settings, 'HTTP_PROXIES', None) or default
        return value

    def oidc_endpoint(self):
        return (super().oidc_endpoint() or '').rstrip('/')

    def decode_access_token(self, access_token):
        """
        Verify a Keycloak access token and return its claims.

        Keycloak issues access tokens as JWTs signed with the realm keys. The audience usually does not
        include our client (it is "account" by default), so instead of `aud` we require the authorized
        party (`azp`) to be this client.
        """
        client_id, _ = self.get_key_and_secret()
        try:
            key = self.find_valid_key(access_token)
            if not key:
                raise AuthTokenError(self, 'Access token signature verification failed')
            claims = jwt.decode(
                access_token,
                jwt.PyJWK(key).key,
                algorithms=self.setting('JWT_ALGORITHMS', self.JWT_ALGORITHMS),
                issuer=self.id_token_issuer(),
                options={'verify_aud': False, 'require': ['exp', 'iss', 'sub']},
                leeway=self.setting('JWT_LEEWAY', self.JWT_LEEWAY),
            )
        except jwt.PyJWTError as e:
            raise AuthTokenError(self, f'Invalid access token: {e}') from e
        if claims.get('azp') != client_id:
            raise AuthTokenError(self, 'Invalid access token: azp')
        return claims

    def get_roles(self, access_token, *claim_sets):
        """
        Return the Keycloak roles and the Keycloak group names found in the verified access token and the
        given claim sets.
        """
        sources = [claims for claims in claim_sets if claims]
        try:
            sources.insert(0, self.decode_access_token(access_token))
        except (AuthTokenError, ValueError) as e:
            logger.warning(f'Unable to read roles from the Keycloak access token: {e}')
        roles, groups = set(), set()
        for claims in sources:
            roles |= extract_roles(claims, self.setting('KEY'))
            groups |= extract_groups(claims)
        return roles, groups

    def user_data(self, access_token, *args, **kwargs):
        data = super().user_data(access_token, *args, **kwargs) or {}
        roles, groups = self.get_roles(access_token, self.id_token, data)
        data['keycloak_roles'] = sorted(roles)
        data['keycloak_groups'] = sorted(groups)
        return data
