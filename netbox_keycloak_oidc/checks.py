from django.conf import settings
from django.core.checks import Error, Warning, register

from .diagnostics import BACKEND_PATH


@register()
def check_configuration(app_configs, **kwargs):
    """
    Static configuration checks, reported by `manage.py check` and on startup.
    """
    if BACKEND_PATH not in settings.AUTHENTICATION_BACKENDS:
        return [Warning(
            'The Keycloak OIDC backend is not enabled; logins via Keycloak are not possible.',
            hint=f"Set REMOTE_AUTH_BACKEND = '{BACKEND_PATH}' in configuration.py.",
            id='netbox_keycloak_oidc.W001',
        )]
    errors = []
    for name in ('OIDC_ENDPOINT', 'KEY', 'SECRET'):
        if not getattr(settings, f'SOCIAL_AUTH_KEYCLOAK_OIDC_{name}', None):
            errors.append(Error(
                f'SOCIAL_AUTH_KEYCLOAK_OIDC_{name} is not set.',
                hint='See the netbox-keycloak-oidc README for the required settings.',
                id='netbox_keycloak_oidc.E001',
            ))
    endpoint = getattr(settings, 'SOCIAL_AUTH_KEYCLOAK_OIDC_OIDC_ENDPOINT', '') or ''
    if endpoint and '/realms/' not in endpoint:
        errors.append(Warning(
            'SOCIAL_AUTH_KEYCLOAK_OIDC_OIDC_ENDPOINT does not look like a Keycloak realm URL.',
            hint='Expected e.g. https://sso.example.com/realms/<realm>',
            id='netbox_keycloak_oidc.W002',
        ))
    if endpoint.startswith('http://'):
        errors.append(Warning(
            'SOCIAL_AUTH_KEYCLOAK_OIDC_OIDC_ENDPOINT uses plain HTTP.',
            hint='Use HTTPS in production.',
            id='netbox_keycloak_oidc.W003',
        ))
    return errors
