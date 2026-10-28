"""
User and group provisioning from Keycloak's SCIM 2.0 API (Keycloak 26.8 or later).

NetBox acts as a SCIM client: a background job reads all users and groups of the realm and creates,
updates and deactivates the corresponding NetBox users, so accounts exist (and are removed) independently
of whether a user ever logs in. Users are linked to Keycloak in the same way as on login (a social auth
association with the Keycloak user ID), so a provisioned user is the same account a later login uses.
"""
import logging
from collections import defaultdict
from dataclasses import dataclass, field

from django.db import transaction
from social_django.models import UserSocialAuth
from social_django.utils import load_backend, load_strategy
from users.models import Group, User

from . import BACKEND_NAME
from .pipeline import apply_roles, mapped_group_names, sync_groups
from .utils import get_setting, is_synced_group

logger = logging.getLogger('netbox_keycloak_oidc.scim')

# Keycloak caps the page size at 100 (ServiceProviderConfig filter.maxResults)
PAGE_SIZE = 100
USER_ATTRIBUTES = 'userName,name,emails,active,groups'
GROUP_ATTRIBUTES = 'displayName,members'


class ScimError(Exception):
    pass


class ScimClient:
    """
    Minimal SCIM 2.0 client for Keycloak, authenticating with the client credentials grant.

    All requests go through the python-social-auth backend, so the backend's VERIFY_SSL, PROXIES and
    REQUESTS_TIMEOUT settings apply here as well.
    """

    def __init__(self):
        self.backend = load_backend(load_strategy(), BACKEND_NAME, redirect_uri=None)
        self.base_url = (get_setting('scim_endpoint') or f'{self.backend.oidc_endpoint()}/scim/v2').rstrip('/')
        self.client_id = get_setting('scim_client_id') or self.backend.setting('KEY')
        self.client_secret = get_setting('scim_client_secret') or self.backend.setting('SECRET')
        self._token = None

    @property
    def token(self):
        if self._token is None:
            response = self.backend.get_json(
                self.backend.access_token_url(),
                method='POST',
                data={'grant_type': 'client_credentials'},
                auth=(self.client_id, self.client_secret),
            )
            self._token = response['access_token']
        return self._token

    def get(self, path, params=None):
        return self.backend.get_json(
            f'{self.base_url}/{path}',
            params=params,
            headers={'Authorization': f'Bearer {self.token}', 'Accept': 'application/scim+json'},
        )

    def list(self, resource, attributes):
        """
        Return all resources of a type, following the pagination.
        """
        resources = []
        start = 1
        while True:
            page = self.get(resource, {'startIndex': start, 'count': PAGE_SIZE, 'attributes': attributes})
            items = page.get('Resources') or []
            resources.extend(items)
            start += len(items)
            if not items or start > page.get('totalResults', 0):
                return resources


@dataclass
class SyncResult:
    created: list = field(default_factory=list)
    updated: list = field(default_factory=list)
    deactivated: list = field(default_factory=list)
    reactivated: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    groups_created: list = field(default_factory=list)

    def __str__(self):
        return ', '.join(f'{name}: {len(getattr(self, name))}' for name in self.__dataclass_fields__)


def primary_email(scim_user):
    emails = scim_user.get('emails') or []
    for email in emails:
        if email.get('primary'):
            return email.get('value') or ''
    return (emails[0].get('value') or '') if emails else ''


def sync_users(client=None, dry_run=False, log=logger):
    """
    Synchronize NetBox users with the users and groups of the Keycloak realm.

    * Users (in scope, see `scim_groups`) are created and linked to their Keycloak user ID.
    * Name and email are kept in sync, group memberships and superuser status follow group_mapping and
      superuser_roles (only as far as SCIM can see them: Keycloak groups, not roles).
    * Users disabled or deleted in Keycloak, or no longer in scope, are deactivated. Users enabled again
      are reactivated.
    """
    client = client or ScimClient()
    groups = client.list('Groups', GROUP_ATTRIBUTES)
    scim_users = client.list('Users', USER_ATTRIBUTES)
    group_names = {group['displayName'] for group in groups if group.get('displayName')}

    memberships = defaultdict(set)
    for group in groups:
        for member in group.get('members') or []:
            memberships[member.get('value')].add(group.get('displayName'))

    scope = set(get_setting('scim_groups'))
    result = SyncResult()
    seen = set()

    with transaction.atomic():
        if get_setting('sync_groups'):
            # Create all mirrored groups, including those without members, so permissions can be assigned
            for name in sorted(name for name in group_names if is_synced_group(name)):
                if name not in mapped_group_names() and not Group.objects.filter(name=name).exists():
                    Group.objects.create(name=name)
                    result.groups_created.append(name)
                    log.info(f'Created group {name}')

        for scim_user in scim_users:
            uid = scim_user.get('id')
            username = scim_user.get('userName')
            if not uid or not username:
                continue
            seen.add(uid)
            if 'active' not in scim_user:
                # Keycloak returns only id and userName for users holding administrative roles in the realm
                log.info(f'Skipping {username}: Keycloak does not expose details of administrative users via SCIM')
                result.skipped.append(username)
                continue

            names = {g.get('display') for g in scim_user.get('groups') or []} | memberships[uid]
            names.discard(None)
            in_scope = not scope or bool(scope & names)
            enabled = bool(scim_user['active']) and in_scope

            social = UserSocialAuth.objects.filter(provider=BACKEND_NAME, uid=uid).select_related('user').first()
            if social:
                user = social.user
            elif not enabled:
                continue
            else:
                user = _create_or_link(username, uid, result, log)
                if user is None:
                    continue

            changed = []
            for attr, value in (
                ('email', primary_email(scim_user)),
                ('first_name', (scim_user.get('name') or {}).get('givenName') or ''),
                ('last_name', (scim_user.get('name') or {}).get('familyName') or ''),
            ):
                if getattr(user, attr) != value:
                    setattr(user, attr, value)
                    changed.append(attr)
            if user.is_active != enabled:
                user.is_active = enabled
                changed.append('is_active')
                (result.reactivated if enabled else result.deactivated).append(username)
                log.info(f'{"Reactivated" if enabled else "Deactivated"} {username}'
                         f'{"" if enabled or scim_user["active"] else " (disabled in Keycloak)"}'
                         f'{"" if in_scope else " (not in scim_groups)"}')
            if changed:
                user.save(update_fields=changed)
                if username not in result.created and changed != ['is_active']:
                    result.updated.append(username)

            if enabled:
                apply_roles(user, names, visible=group_names)
                if get_setting('sync_groups'):
                    sync_groups(user, names)

        # Users deleted in Keycloak
        if get_setting('scim_deactivate_missing'):
            stale = UserSocialAuth.objects.filter(provider=BACKEND_NAME, user__is_active=True).exclude(uid__in=seen)
            if stale.exists() and not scim_users:
                log.error('Keycloak returned no users at all; not deactivating anyone. Check the SCIM permissions.')
            else:
                for social in stale.select_related('user'):
                    social.user.is_active = False
                    social.user.save(update_fields=['is_active'])
                    result.deactivated.append(social.user.username)
                    log.info(f'Deactivated {social.user.username} (deleted in Keycloak)')

        if dry_run:
            transaction.set_rollback(True)

    log.info(f'SCIM sync {"(dry run) " if dry_run else ""}finished: {result}')
    return result


def _create_or_link(username, uid, result, log):
    existing = User.objects.filter(username=username).first()
    if existing is not None:
        if existing.social_auth.filter(provider=BACKEND_NAME).exists() or not get_setting('link_existing_users'):
            log.warning(f'Skipping {username}: a NetBox user with this name exists and is not linked to Keycloak')
            result.skipped.append(username)
            return None
        user = existing
        log.info(f'Linked existing NetBox user {username} to Keycloak')
    else:
        user = User(username=username)
        user.set_unusable_password()
        user.save()
        result.created.append(username)
        log.info(f'Created {username}')
    UserSocialAuth.objects.create(user=user, provider=BACKEND_NAME, uid=uid, extra_data={})
    return user
