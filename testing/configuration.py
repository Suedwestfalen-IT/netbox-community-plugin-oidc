# NetBox configuration for running the plugin's test suite:
#   NETBOX_CONFIGURATION=testing.configuration python manage.py test netbox_keycloak_oidc
# (with the plugin repository root on PYTHONPATH)
from netbox.configuration_testing import *  # noqa: F403

PLUGINS = ['netbox_keycloak_oidc']
PLUGINS_CONFIG = {'netbox_keycloak_oidc': {}}

REMOTE_AUTH_BACKEND = 'netbox_keycloak_oidc.backends.KeycloakOIDC'
SOCIAL_AUTH_KEYCLOAK_OIDC_OIDC_ENDPOINT = 'https://keycloak.test/realms/netbox'
SOCIAL_AUTH_KEYCLOAK_OIDC_KEY = 'netbox'
SOCIAL_AUTH_KEYCLOAK_OIDC_SECRET = 'secret'
