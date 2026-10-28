from django.conf import settings
from netbox.plugins import get_plugin_config

PLUGIN_NAME = 'netbox_keycloak_oidc'

# Keys used to keep per-session OIDC state in the Django session
SESSION_REFRESH_TOKEN = 'keycloak_oidc_refresh_token'
SESSION_ID_TOKEN = 'keycloak_oidc_id_token'
SESSION_SUBJECT = 'keycloak_oidc_sub'
SESSION_LAST_CHECK = 'keycloak_oidc_last_check'


def get_setting(name):
    from . import KeycloakOIDCConfig

    return get_plugin_config(PLUGIN_NAME, name, KeycloakOIDCConfig.default_settings.get(name))


def get_client_id():
    return getattr(settings, 'SOCIAL_AUTH_KEYCLOAK_OIDC_KEY', None)


def extract_roles(claims, client_id=None, sources=None):
    """
    Collect the Keycloak roles of a user from a set of token/userinfo claims.

    Realm roles are read from `realm_access.roles`, client roles from `resource_access.<client>.roles`
    and group memberships from `groups` (a leading slash and parent paths are kept as-is, but the
    plain group name is added as well, so both "/netbox/admins" and "admins" match).
    """
    if sources is None:
        sources = get_setting('role_sources')
    if client_id is None:
        client_id = get_client_id()

    roles = set()
    if 'realm' in sources:
        roles.update((claims.get('realm_access') or {}).get('roles') or [])
    if 'client' in sources and client_id:
        roles.update(((claims.get('resource_access') or {}).get(client_id) or {}).get('roles') or [])
    if 'groups' in sources:
        for group in claims.get('groups') or []:
            roles.add(group)
            roles.add(group.rstrip('/').rsplit('/', 1)[-1])
    roles.discard('')
    return roles


def group_name(group):
    """
    Return the plain name of a Keycloak group given as a path ("/parent/child") or a name.
    """
    return (group or '').rstrip('/').rsplit('/', 1)[-1]


def extract_groups(claims):
    """
    Return the names of the Keycloak groups listed in the "groups" claim.
    """
    names = {group_name(group) for group in claims.get('groups') or [] if isinstance(group, str)}
    names.discard('')
    return names


def is_synced_group(name):
    """
    Whether a Keycloak group is mirrored to NetBox by sync_groups (prefix filter and exclusions).
    """
    return (
        bool(name)
        and name.startswith(get_setting('sync_groups_prefix') or '')
        and name not in set(get_setting('sync_groups_exclude') or [])
    )
