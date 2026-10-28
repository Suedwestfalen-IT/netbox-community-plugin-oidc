"""
python-social-auth pipeline steps for the Keycloak OIDC backend.

The plugin installs these steps automatically for the `keycloak-oidc` backend (see `install_pipeline()`),
unless SOCIAL_AUTH_KEYCLOAK_OIDC_PIPELINE is defined explicitly in configuration.py. All steps ignore any
other social auth backend.
"""
import logging
import time

from django.conf import settings
from social_core.exceptions import AuthForbidden
from users.models import Group, User

from . import BACKEND_NAME
from .utils import (
    SESSION_ID_TOKEN,
    SESSION_LAST_CHECK,
    SESSION_REFRESH_TOKEN,
    SESSION_SUBJECT,
    get_setting,
    is_synced_group,
)

logger = logging.getLogger('netbox_keycloak_oidc.pipeline')

# Request attribute used to hand the OIDC tokens over to the user_logged_in signal handler
REQUEST_TOKENS_ATTR = '_keycloak_oidc_tokens'

CHECK_ACCESS = 'netbox_keycloak_oidc.pipeline.check_access'
LINK_EXISTING_USER = 'netbox_keycloak_oidc.pipeline.link_existing_user'
SYNC_ROLES = 'netbox_keycloak_oidc.pipeline.sync_roles'
REMEMBER_TOKENS = 'netbox_keycloak_oidc.pipeline.remember_tokens'


def build_pipeline(base_pipeline):
    """
    Extend a pipeline with the Keycloak steps. The access check runs before the user is looked up or
    created, so users lacking a required role never get a NetBox account.
    """
    steps = (CHECK_ACCESS, LINK_EXISTING_USER, SYNC_ROLES, REMEMBER_TOKENS)
    pipeline = [step for step in base_pipeline if step not in steps]
    anchor = 'social_core.pipeline.social_auth.social_uid'
    index = pipeline.index(anchor) + 1 if anchor in pipeline else 0
    pipeline.insert(index, CHECK_ACCESS)
    anchor = 'social_core.pipeline.social_auth.social_user'
    if anchor in pipeline:
        pipeline.insert(pipeline.index(anchor) + 1, LINK_EXISTING_USER)
    pipeline += [SYNC_ROLES, REMEMBER_TOKENS]
    return tuple(pipeline)


def install_pipeline():
    if not hasattr(settings, 'SOCIAL_AUTH_KEYCLOAK_OIDC_PIPELINE'):
        settings.SOCIAL_AUTH_KEYCLOAK_OIDC_PIPELINE = build_pipeline(settings.SOCIAL_AUTH_PIPELINE)


def _roles(response):
    return set((response or {}).get('keycloak_roles') or [])


def check_access(backend, response, details=None, *args, **kwargs):
    """
    Deny the login if required roles are configured and the user holds none of them.
    """
    if backend.name != BACKEND_NAME:
        return
    required_roles = set(get_setting('required_roles'))
    if required_roles and not required_roles & _roles(response):
        username = (details or {}).get('username') or response.get('sub')
        logger.warning(f'Keycloak login denied for {username}: none of the required roles {sorted(required_roles)}')
        raise AuthForbidden(backend)


def link_existing_user(backend, details, user=None, *args, **kwargs):
    """
    If enabled, use an existing NetBox user of the same name that is not yet linked to Keycloak, instead of
    letting python-social-auth create a new user with a random suffix. associate_user links it afterwards.
    """
    if backend.name != BACKEND_NAME or user is not None or not get_setting('link_existing_users'):
        return None
    username = (details or {}).get('username')
    existing = User.objects.filter(username=username).first() if username else None
    if existing is None or existing.social_auth.filter(provider=BACKEND_NAME).exists():
        return None
    logger.info(f'Linking existing NetBox user {username} to Keycloak')
    return {'user': existing}


def sync_roles(backend, user, response, *args, **kwargs):
    """
    Map Keycloak roles to NetBox groups and the superuser flag.
    """
    if backend.name != BACKEND_NAME or user is None:
        return
    apply_roles(user, _roles(response))
    if get_setting('sync_groups'):
        sync_groups(user, set((response or {}).get('keycloak_groups') or []))


def apply_roles(user, roles, visible=None):
    """
    Apply superuser_roles and group_mapping to a user holding the given Keycloak roles.

    `visible` is the set of role names the caller is able to see (None: all of them). SCIM only exposes
    Keycloak groups, not roles, so a sync must not revoke anything that might be granted by a role it
    cannot see: superuser status is only revoked if all superuser_roles are visible, and NetBox groups
    are only removed if every mapping entry leading to them is visible.
    """
    def is_visible(role):
        return visible is None or role in visible

    superuser_roles = set(get_setting('superuser_roles'))
    if superuser_roles:
        if superuser_roles & roles:
            is_superuser = True
        elif all(is_visible(role) for role in superuser_roles):
            is_superuser = False
        else:
            is_superuser = user.is_superuser
        if user.is_superuser != is_superuser:
            user.is_superuser = is_superuser
            user.save(update_fields=['is_superuser'])
            logger.info(f'Set is_superuser={is_superuser} for {user} from Keycloak roles')

    group_mapping = get_setting('group_mapping') or {}
    if not group_mapping:
        return

    def as_list(value):
        return [value] if isinstance(value, str) else list(value)

    wanted = {name for role, names in group_mapping.items() if role in roles for name in as_list(names)}
    managed = {name for role, names in group_mapping.items() if is_visible(role) for name in as_list(names)}
    managed -= {name for role, names in group_mapping.items() if not is_visible(role) for name in as_list(names)}

    groups = []
    for name in sorted(wanted):
        if get_setting('auto_create_groups'):
            group, created = Group.objects.get_or_create(name=name)
            if created:
                logger.info(f'Created NetBox group {name}')
        else:
            group = Group.objects.filter(name=name).first()
            if group is None:
                logger.error(f'Cannot assign group {name} to {user}: group does not exist')
                continue
        groups.append(group)
    new_groups = [group for group in groups if not user.groups.filter(pk=group.pk).exists()]
    if new_groups:
        logger.info(f'Adding {user} to groups {sorted(group.name for group in new_groups)}')
        user.groups.add(*new_groups)

    if get_setting('remove_unmapped_groups'):
        stale = user.groups.filter(name__in=managed - wanted)
        if stale.exists():
            logger.info(f'Removing {user} from groups {sorted(stale.values_list("name", flat=True))}')
            user.groups.remove(*stale)


def mapped_group_names():
    group_mapping = get_setting('group_mapping') or {}
    return {name for names in group_mapping.values() for name in ([names] if isinstance(names, str) else names)}


def sync_groups(user, keycloak_groups):
    """
    Mirror Keycloak groups as NetBox groups of the same name (see the sync_groups setting).

    The user is added to (and, if necessary, creates) the NetBox group of each Keycloak group that passes the
    prefix/exclusion filter, and removed from every other NetBox group that passes the filter. Groups that are
    targets of group_mapping are left to the mapping.
    """
    mapped = mapped_group_names()
    wanted = {name for name in keycloak_groups if is_synced_group(name)} - mapped

    groups = []
    for name in sorted(wanted):
        group, created = Group.objects.get_or_create(name=name)
        if created:
            logger.info(f'Created NetBox group {name} from Keycloak')
        groups.append(group)
    new_groups = [group for group in groups if not user.groups.filter(pk=group.pk).exists()]
    if new_groups:
        logger.info(f'Adding {user} to groups {sorted(group.name for group in new_groups)}')
        user.groups.add(*new_groups)

    stale = [
        group for group in user.groups.exclude(name__in=wanted | mapped)
        if is_synced_group(group.name)
    ]
    if stale:
        logger.info(f'Removing {user} from groups {sorted(group.name for group in stale)}')
        user.groups.remove(*stale)


def remember_tokens(strategy, backend, response, *args, **kwargs):
    """
    Keep the tokens of this login for session validation and logout. They are written to the session
    once the user has been logged in (see signals.py), since Django may flush the session on login.
    """
    if backend.name != BACKEND_NAME or strategy.request is None:
        return
    setattr(strategy.request, REQUEST_TOKENS_ATTR, {
        SESSION_REFRESH_TOKEN: response.get('refresh_token'),
        SESSION_ID_TOKEN: response.get('id_token'),
        SESSION_SUBJECT: (backend.id_token or {}).get('sub'),
        SESSION_LAST_CHECK: time.time(),
    })
