from netbox.plugins import PluginConfig

__version__ = '0.1.0'

# Name of the python-social-auth backend provided by this plugin
BACKEND_NAME = 'keycloak-oidc'


class KeycloakOIDCConfig(PluginConfig):
    name = 'netbox_keycloak_oidc'
    verbose_name = 'Keycloak OIDC'
    description = 'Login to NetBox via Keycloak (OpenID Connect) with role mapping and session validation'
    version = __version__
    author = 'Suedwestfalen-IT'
    base_url = 'keycloak-oidc'
    min_version = '4.4.0'
    middleware = [
        'netbox_keycloak_oidc.middleware.KeycloakSessionMiddleware',
    ]
    default_settings = {
        # Display name of the login button
        'button_label': 'Keycloak',
        # Where Keycloak roles are read from: realm roles, roles of this client, group memberships
        'role_sources': ['realm', 'client', 'groups'],
        # A user must hold at least one of these roles to log in (empty: everyone may log in)
        'required_roles': [],
        # Users holding one of these roles become superusers; all others lose superuser status
        'superuser_roles': [],
        # Maps a Keycloak role to one or more NetBox group names, e.g. {'netbox-admins': ['Admins']}
        'group_mapping': {},
        # Create NetBox groups listed in group_mapping if they do not exist yet
        'auto_create_groups': False,
        # Remove mapped NetBox groups from a user once the corresponding role is gone
        'remove_unmapped_groups': True,
        # Seconds between re-validations of a NetBox session against Keycloak (0 disables)
        'session_check_interval': 300,
        # Log users out if Keycloak cannot be reached during re-validation
        'session_check_fail_closed': False,
        # Terminate the Keycloak SSO session when the user logs out of NetBox
        'logout_from_keycloak': True,
    }

    def ready(self):
        super().ready()
        from . import checks, signals  # noqa: F401
        from .pipeline import install_pipeline

        install_pipeline()
        self._register_button_label()

    def _register_button_label(self):
        """
        Give the login button a friendly name unless SOCIAL_AUTH_BACKEND_ATTRS already defines one.
        """
        try:
            from netbox.authentication import AUTH_BACKEND_ATTRS
        except ImportError:
            return
        from .utils import get_setting

        AUTH_BACKEND_ATTRS.setdefault(BACKEND_NAME, (get_setting('button_label'), 'login'))


config = KeycloakOIDCConfig
