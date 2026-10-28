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
from users.models import Group

from . import BACKEND_NAME
from .utils import (
    SESSION_ID_TOKEN,
    SESSION_LAST_CHECK,
    SESSION_REFRESH_TOKEN,
    SESSION_SUBJECT,
    get_setting,
)

logger = logging.getLogger('netbox_keycloak_oidc.pipeline')

# Request attribute used to hand the OIDC tokens over to the user_logged_in signal handler
REQUEST_TOKENS_ATTR = '_keycloak_oidc_tokens'

CHECK_ACCESS = 'netbox_keycloak_oidc.pipeline.check_access'
SYNC_ROLES = 'netbox_keycloak_oidc.pipeline.sync_roles'
REMEMBER_TOKENS = 'netbox_keycloak_oidc.pipeline.remember_tokens'


def build_pipeline(base_pipeline):
    """
    Extend a pipeline with the Keycloak steps. The access check runs before the user is looked up or
    created, so users lacking a required role never get a NetBox account.
    """
    pipeline = [step for step in base_pipeline if step not in (CHECK_ACCESS, SYNC_ROLES, REMEMBER_TOKENS)]
    anchor = 'social_core.pipeline.social_auth.social_uid'
    index = pipeline.index(anchor) + 1 if anchor in pipeline else 0
    pipeline.insert(index, CHECK_ACCESS)
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


def sync_roles(backend, user, response, *args, **kwargs):
    """
    Map Keycloak roles to NetBox groups and the superuser flag.
    """
    if backend.name != BACKEND_NAME or user is None:
        return
    roles = _roles(response)

    superuser_roles = set(get_setting('superuser_roles'))
    if superuser_roles:
        is_superuser = bool(superuser_roles & roles)
        if user.is_superuser != is_superuser:
            user.is_superuser = is_superuser
            user.save(update_fields=['is_superuser'])
            logger.info(f'Set is_superuser={is_superuser} for {user} from Keycloak roles')

    group_mapping = get_setting('group_mapping') or {}
    if not group_mapping:
        return

    def as_list(value):
        return [value] if isinstance(value, str) else list(value)

    managed = {name for names in group_mapping.values() for name in as_list(names)}
    wanted = {name for role, names in group_mapping.items() if role in roles for name in as_list(names)}

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
    if groups:
        user.groups.add(*groups)

    if get_setting('remove_unmapped_groups'):
        stale = user.groups.filter(name__in=managed - wanted)
        if stale.exists():
            logger.info(f'Removing {user} from groups {sorted(stale.values_list("name", flat=True))}')
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
