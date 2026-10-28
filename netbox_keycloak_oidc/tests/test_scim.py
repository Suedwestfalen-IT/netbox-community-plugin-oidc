from io import StringIO

from django.core.management import call_command
from django.test import override_settings
from django.urls import reverse
from social_django.utils import load_backend, load_strategy
from users.models import Group, User

from netbox_keycloak_oidc import BACKEND_NAME
from netbox_keycloak_oidc.diagnostics import FAILED, OK, run_diagnostics
from netbox_keycloak_oidc.scim import sync_users

from .keycloak import SCIM_CLIENT_ID, SCIM_CLIENT_SECRET
from .test_login import KeycloakTestCase

SCIM = {'scim_enabled': True, 'scim_client_id': SCIM_CLIENT_ID, 'scim_client_secret': SCIM_CLIENT_SECRET}


def scim_config(**kwargs):
    return override_settings(PLUGINS_CONFIG={'netbox_keycloak_oidc': {**SCIM, **kwargs}})


@scim_config()
class ScimSyncTest(KeycloakTestCase):

    def usernames(self, **filters):
        return set(User.objects.filter(**filters).values_list('username', flat=True))

    def test_provisioning(self):
        self.keycloak.add_user('alice', email='alice@example.com')
        self.keycloak.add_user('bob')
        result = sync_users()
        self.assertEqual(sorted(result.created), ['alice', 'bob'])

        alice = User.objects.get(username='alice')
        self.assertEqual((alice.email, alice.first_name, alice.last_name), ('alice@example.com', 'Alice', 'Test'))
        self.assertTrue(alice.is_active)
        self.assertFalse(alice.has_usable_password())
        self.assertEqual(alice.social_auth.get().uid, self.keycloak.users['alice']['sub'])
        self.assertEqual(alice.social_auth.get().provider, BACKEND_NAME)

        # A second run changes nothing
        result = sync_users()
        self.assertEqual((result.created, result.updated, result.deactivated), ([], [], []))

    def test_login_uses_provisioned_user(self):
        self.keycloak.add_user('alice')
        sync_users()
        self.login('alice')
        self.assertLoggedIn('alice')
        self.assertEqual(User.objects.count(), 1)

    def test_provisioned_user_logged_in_first(self):
        self.keycloak.add_user('alice')
        self.login('alice')
        self.client.logout()
        result = sync_users()
        self.assertEqual(result.created, [])
        self.assertEqual(User.objects.count(), 1)

    def test_update_details(self):
        self.keycloak.add_user('alice')
        sync_users()
        self.keycloak.users['alice'].update(email='new@example.com', family_name='Renamed')
        result = sync_users()
        self.assertEqual(result.updated, ['alice'])
        alice = User.objects.get(username='alice')
        self.assertEqual((alice.email, alice.last_name), ('new@example.com', 'Renamed'))

    def test_disable_and_enable(self):
        self.keycloak.add_user('alice')
        sync_users()
        self.keycloak.users['alice']['enabled'] = False
        self.assertEqual(sync_users().deactivated, ['alice'])
        self.assertFalse(User.objects.get(username='alice').is_active)

        self.keycloak.users['alice']['enabled'] = True
        self.assertEqual(sync_users().reactivated, ['alice'])
        self.assertTrue(User.objects.get(username='alice').is_active)

    def test_disabled_user_not_created(self):
        self.keycloak.add_user('alice')['enabled'] = False
        sync_users()
        self.assertFalse(User.objects.exists())

    def test_deleted_user_deactivated_and_logged_out(self):
        self.keycloak.add_user('alice')
        self.keycloak.add_user('bob')
        self.login('alice')
        sync_users()
        del self.keycloak.users['alice']
        self.assertEqual(sync_users().deactivated, ['alice'])
        self.assertEqual(self.usernames(is_active=True), {'bob'})
        # The existing session is no longer valid
        response = self.client.get(reverse('dcim:site_list'))
        self.assertEqual(response.status_code, 302)

    def test_no_mass_deactivation_on_empty_response(self):
        self.keycloak.add_user('alice')
        sync_users()
        self.keycloak.users.clear()
        self.assertEqual(sync_users().deactivated, [])
        self.assertTrue(User.objects.get(username='alice').is_active)

    @scim_config(scim_deactivate_missing=False)
    def test_keep_deleted_users(self):
        self.keycloak.add_user('alice')
        self.keycloak.add_user('bob')
        sync_users()
        del self.keycloak.users['alice']
        sync_users()
        self.assertTrue(User.objects.get(username='alice').is_active)

    def test_local_users_untouched(self):
        User.objects.create_user(username='local', password='x')
        self.keycloak.add_user('alice')
        sync_users()
        self.assertTrue(User.objects.get(username='local').is_active)

    def test_admin_users_skipped(self):
        self.keycloak.add_user('alice')
        sync_users()
        self.keycloak.users['alice']['admin'] = True
        self.keycloak.add_user('root')['admin'] = True
        result = sync_users()
        self.assertEqual(sorted(result.skipped), ['alice', 'root'])
        self.assertTrue(User.objects.get(username='alice').is_active)
        self.assertFalse(User.objects.filter(username='root').exists())

    @scim_config(scim_groups=['netbox'])
    def test_scope(self):
        self.keycloak.add_user('alice', groups=['/netbox'])
        self.keycloak.add_user('bob')
        sync_users()
        self.assertEqual(self.usernames(), {'alice'})

        self.keycloak.users['alice']['groups'] = []
        self.assertEqual(sync_users().deactivated, ['alice'])

    def test_existing_user_not_linked(self):
        User.objects.create_user(username='alice', password='x', is_superuser=True)
        self.keycloak.add_user('alice')
        result = sync_users()
        self.assertEqual(result.skipped, ['alice'])
        self.assertFalse(User.objects.get(username='alice').social_auth.exists())

    @scim_config(link_existing_users=True)
    def test_existing_user_linked(self):
        User.objects.create_user(username='alice', password='x')
        self.keycloak.add_user('alice')
        sync_users()
        self.assertEqual(User.objects.get(username='alice').social_auth.get().uid, self.keycloak.users['alice']['sub'])

    @scim_config(group_mapping={'netbox-operators': 'Operators', 'ops-role': 'Operators', 'admins': 'Admins'},
                 auto_create_groups=True)
    def test_group_mapping(self):
        self.keycloak.add_user('dave', groups=['/netbox-operators', '/admins'])
        self.keycloak.add_user('erin', groups=['/admins'])
        sync_users()
        dave = User.objects.get(username='dave')
        self.assertEqual(set(dave.groups.values_list('name', flat=True)), {'Operators', 'Admins'})

        self.keycloak.users['dave']['groups'] = []
        sync_users()
        # "Admins" is only granted via a Keycloak group and removed; "Operators" may also come from the role
        # "ops-role", which SCIM cannot see, so it is kept
        self.assertEqual(set(dave.groups.values_list('name', flat=True)), {'Operators'})

    @scim_config(superuser_roles=['netbox-admins'])
    def test_superuser_group(self):
        self.keycloak.add_user('carol', groups=['/netbox-admins'])
        self.keycloak.add_user('other', groups=['/netbox-admins'])
        sync_users()
        self.assertTrue(User.objects.get(username='carol').is_superuser)
        self.keycloak.users['carol']['groups'] = []
        sync_users()
        self.assertFalse(User.objects.get(username='carol').is_superuser)

    @scim_config(superuser_roles=['netbox-admin-role'])
    def test_superuser_role_not_revoked(self):
        self.keycloak.add_user('carol', realm_roles=['netbox-admin-role'])
        self.login('carol')
        self.assertTrue(User.objects.get(username='carol').is_superuser)
        sync_users()
        self.assertTrue(User.objects.get(username='carol').is_superuser)

    def test_pagination(self):
        self.keycloak.scim_page_size = 2
        for name in ('u1', 'u2', 'u3', 'u4', 'u5'):
            self.keycloak.add_user(name)
        self.assertEqual(len(sync_users().created), 5)

    def test_dry_run(self):
        self.keycloak.add_user('alice')
        result = sync_users(dry_run=True)
        self.assertEqual(result.created, ['alice'])
        self.assertFalse(User.objects.exists())
        self.assertFalse(Group.objects.exists())

    def test_management_command(self):
        self.keycloak.add_user('alice')
        out = StringIO()
        call_command('keycloak_scim_sync', stdout=out)
        self.assertIn('Created alice', out.getvalue())
        self.assertTrue(User.objects.filter(username='alice').exists())

    def test_diagnostics(self):
        self.keycloak.add_user('alice')
        results = {r.name: r for r in run_diagnostics()}
        for name in ('SCIM token', 'SCIM audience', 'SCIM Users', 'SCIM Groups'):
            self.assertEqual(results[name].status, OK, results[name])

    def test_diagnostics_missing_audience(self):
        self.keycloak.scim_audience = False
        results = {r.name: r for r in run_diagnostics()}
        self.assertEqual(results['SCIM audience'].status, FAILED)

    def test_diagnostics_scim_disabled(self):
        self.keycloak.scim_enabled = False
        results = {r.name: r for r in run_diagnostics()}
        self.assertEqual(results['SCIM Users'].status, FAILED)
        self.assertIn('Realm settings', results['SCIM Users'].detail)

    def test_status_view(self):
        self.client.force_login(User.objects.create_user(username='admin', password='x', is_superuser=True))
        response = self.client.get(reverse('plugins:netbox_keycloak_oidc:status'))
        self.assertContains(response, 'SCIM synchronization')
        self.assertContains(response, 'Keycloak connection OK')

    @scim_config(scim_client_secret='wrong')
    def test_diagnostics_wrong_secret(self):
        results = {r.name: r for r in run_diagnostics()}
        self.assertEqual(results['SCIM token'].status, FAILED)


class LinkExistingUserTest(KeycloakTestCase):

    def setUp(self):
        super().setUp()
        self.local = User.objects.create_user(username='alice', password='x')
        self.keycloak.add_user('alice')

    def test_not_linked_by_default(self):
        self.login('alice')
        user = User.objects.get(social_auth__provider=BACKEND_NAME)
        self.assertNotEqual(user.pk, self.local.pk)
        self.assertTrue(user.username.startswith('alice'))

    @override_settings(PLUGINS_CONFIG={'netbox_keycloak_oidc': {'link_existing_users': True}})
    def test_linked(self):
        self.login('alice')
        self.assertLoggedIn('alice')
        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(self.local.social_auth.get().uid, self.keycloak.users['alice']['sub'])


class ProxyTest(KeycloakTestCase):

    def backend(self):
        return load_backend(load_strategy(), BACKEND_NAME, redirect_uri=None)

    @override_settings(HTTP_PROXIES={'https': 'http://proxy.test:3128'})
    def test_netbox_http_proxies(self):
        self.assertEqual(self.backend().setting('PROXIES'), {'https': 'http://proxy.test:3128'})

    @override_settings(HTTP_PROXIES={'https': 'http://proxy.test:3128'},
                       SOCIAL_AUTH_KEYCLOAK_OIDC_PROXIES={'https': 'http://other.test:8080'})
    def test_explicit_proxies(self):
        self.assertEqual(self.backend().setting('PROXIES'), {'https': 'http://other.test:8080'})


class GroupSyncTest(KeycloakTestCase):

    def groups_of(self, username):
        return set(User.objects.get(username=username).groups.values_list('name', flat=True))

    @override_settings(PLUGINS_CONFIG={'netbox_keycloak_oidc': {'sync_groups': True}})
    def test_login_creates_groups(self):
        self.keycloak.add_user('alice', groups=['/dc-ops', '/parent/dc-net', '/netbox-admin'], realm_roles=['role'])
        self.login('alice')
        # Keycloak groups are mirrored (by plain name), roles and the excluded default groups are not
        self.assertEqual(self.groups_of('alice'), {'dc-ops', 'dc-net'})
        self.assertFalse(Group.objects.filter(name__in=['netbox-admin', 'role']).exists())

        # Leaving a Keycloak group removes the membership on the next login, the NetBox group stays
        self.client.logout()
        self.keycloak.users['alice']['groups'] = ['/dc-ops']
        self.login('alice')
        self.assertEqual(self.groups_of('alice'), {'dc-ops'})
        self.assertTrue(Group.objects.filter(name='dc-net').exists())

    @override_settings(PLUGINS_CONFIG={'netbox_keycloak_oidc': {'sync_groups': True, 'sync_groups_prefix': 'nb-'}})
    def test_prefix(self):
        local = Group.objects.create(name='local-group')
        self.keycloak.add_user('alice', groups=['/nb-ops', '/other'])
        self.login('alice')
        User.objects.get(username='alice').groups.add(local)
        self.assertEqual(self.groups_of('alice'), {'nb-ops', 'local-group'})
        self.assertFalse(Group.objects.filter(name='other').exists())

        # Groups without the prefix are not managed by Keycloak
        self.client.logout()
        self.keycloak.users['alice']['groups'] = []
        self.login('alice')
        self.assertEqual(self.groups_of('alice'), {'local-group'})

    @override_settings(PLUGINS_CONFIG={'netbox_keycloak_oidc': {
        'sync_groups': True, 'group_mapping': {'netbox-user': ['Readers']}, 'auto_create_groups': True,
    }})
    def test_with_group_mapping(self):
        self.keycloak.add_user('alice', groups=['/ops'], client_roles=['netbox-user'])
        self.login('alice')
        self.assertEqual(self.groups_of('alice'), {'ops', 'Readers'})

    def test_disabled_by_default(self):
        self.keycloak.add_user('alice', groups=['/ops'])
        self.login('alice')
        self.assertEqual(self.groups_of('alice'), set())

    @scim_config(sync_groups=True, sync_groups_prefix='nb-')
    def test_scim(self):
        self.keycloak.add_user('alice', groups=['/nb-ops', '/other'])
        self.keycloak.add_user('bob', groups=['/nb-empty-later'])
        result = sync_users()
        self.assertEqual(sorted(result.groups_created), ['nb-empty-later', 'nb-ops'])
        self.assertEqual(self.groups_of('alice'), {'nb-ops'})

        self.keycloak.users['alice']['groups'] = ['/nb-new']
        sync_users()
        self.assertEqual(self.groups_of('alice'), {'nb-new'})
