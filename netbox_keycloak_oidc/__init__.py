from netbox.plugins import PluginConfig

__version__ = '0.2.0'

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
        # Mirror the user's Keycloak groups (the "groups" claim, or SCIM) as NetBox groups of the same name:
        # create them and keep memberships in sync. NetBox groups matching the filter below are managed
        # entirely by Keycloak (users are removed from them when they leave the Keycloak group).
        'sync_groups': False,
        # Only mirror Keycloak groups whose name starts with this prefix (empty: all groups)
        'sync_groups_prefix': '',
        # Keycloak groups that are never mirrored
        'sync_groups_exclude': ['netbox-admin', 'netbox-user'],
        # Create NetBox groups listed in group_mapping if they do not exist yet
        'auto_create_groups': False,
        # Remove mapped NetBox groups from a user once the corresponding role is gone
        'remove_unmapped_groups': True,
        # On login and SCIM sync, link a Keycloak user to an existing NetBox user of the same name that is not
        # linked to Keycloak yet (otherwise a new user with a random suffix is created). Only enable this if
        # usernames in Keycloak are trustworthy: a Keycloak user could otherwise take over a local account.
        'link_existing_users': False,
        # Seconds between re-validations of a NetBox session against Keycloak (0 disables)
        'session_check_interval': 300,
        # Log users out if Keycloak cannot be reached during re-validation
        'session_check_fail_closed': False,
        # Terminate the Keycloak SSO session when the user logs out of NetBox
        'logout_from_keycloak': True,
        # Provision users and groups from Keycloak's SCIM API (Keycloak >= 26.8)
        'scim_enabled': False,
        # SCIM base URL (default: <SOCIAL_AUTH_KEYCLOAK_OIDC_OIDC_ENDPOINT>/scim/v2)
        'scim_endpoint': None,
        # Service account client for SCIM (default: the login client)
        'scim_client_id': None,
        'scim_client_secret': None,
        # Minutes between synchronizations by the background job
        'scim_sync_interval': 60,
        # Only provision members of these Keycloak groups (empty: all users of the realm)
        'scim_groups': [],
        # Deactivate NetBox users whose Keycloak account has been deleted
        'scim_deactivate_missing': True,
    }

    def ready(self):
        super().ready()
        from . import checks, signals  # noqa: F401
        from .pipeline import install_pipeline
        from .utils import get_setting

        install_pipeline()
        if get_setting('scim_enabled'):
            from . import jobs  # noqa: F401
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
