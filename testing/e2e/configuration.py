# NetBox configuration for the end-to-end test against a local Keycloak (see README.md)
from netbox.configuration_testing import *  # noqa: F403

DATABASES = {'default': {'NAME': 'netbox_e2e', 'USER': 'netbox', 'PASSWORD': 'netbox', 'HOST': 'localhost'}}
SECRET_KEY = 'e2e-secret-key-e2e-secret-key-e2e-secret-key-e2e-secret-key-1234'
DEBUG = False
ALLOWED_HOSTS = ['*']
PLUGINS = ['netbox_keycloak_oidc']
PLUGINS_CONFIG = {
    'netbox_keycloak_oidc': {
        'required_roles': ['netbox-user', 'netbox-admin'],
        'superuser_roles': ['netbox-admin'],
        'group_mapping': {'netbox-operators': ['Operators'], 'netbox-user': ['Readers']},
        'auto_create_groups': True,
        'session_check_interval': 5,
        'sync_groups': True,
        'sync_groups_prefix': 'nb-',
        'scim_enabled': True,
        'scim_client_id': 'netbox-scim',
        'scim_client_secret': 'scim-secret',
        'scim_sync_interval': 1,
    },
}
REMOTE_AUTH_BACKEND = 'netbox_keycloak_oidc.backends.KeycloakOIDC'
SOCIAL_AUTH_KEYCLOAK_OIDC_OIDC_ENDPOINT = 'http://localhost:8080/realms/netbox'
SOCIAL_AUTH_KEYCLOAK_OIDC_KEY = 'netbox'
SOCIAL_AUTH_KEYCLOAK_OIDC_SECRET = 'netbox-secret'
LOGGING = {
    'version': 1,
    'handlers': {'console': {'class': 'logging.StreamHandler'}},
    'loggers': {'netbox_keycloak_oidc': {'handlers': ['console'], 'level': 'DEBUG'}},
}
