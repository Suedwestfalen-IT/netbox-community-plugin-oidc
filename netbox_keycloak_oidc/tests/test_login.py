import time
from urllib.parse import parse_qs, urlparse

from django.conf import settings
from django.test import TestCase, override_settings
from django.urls import NoReverseMatch, reverse
from users.models import Group, User

from netbox_keycloak_oidc.pipeline import CHECK_ACCESS, REMEMBER_TOKENS, SYNC_ROLES, build_pipeline
from netbox_keycloak_oidc.utils import (
    SESSION_ID_TOKEN,
    SESSION_LAST_CHECK,
    SESSION_REFRESH_TOKEN,
    SESSION_SUBJECT,
    extract_roles,
)

from .keycloak import ISSUER, FakeKeycloak, generate_key


def begin_url():
    try:
        # NetBox >= 4.6 wraps the social auth begin view (POST only)
        return reverse('social_auth_begin', args=['keycloak-oidc'])
    except NoReverseMatch:
        return reverse('social:begin', args=['keycloak-oidc'])


def plugin_config(**kwargs):
    return override_settings(PLUGINS_CONFIG={'netbox_keycloak_oidc': kwargs})


class KeycloakTestCase(TestCase):

    def setUp(self):
        self.keycloak = FakeKeycloak()
        patcher = self.keycloak.running()
        patcher.__enter__()
        self.addCleanup(patcher.__exit__, None, None, None)

    def begin(self):
        return self.client.post(begin_url())

    def login(self, username):
        response = self.begin()
        self.assertEqual(response.status_code, 302)
        params = self.keycloak.authorize(response['Location'], username)
        return self.client.get(reverse('social:complete', args=['keycloak-oidc']), params)

    def assertLoggedIn(self, username):
        response = self.client.get(reverse('home'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['request'].user.username, username)

    def assertLoggedOut(self):
        self.assertNotIn('_auth_user_id', self.client.session)


class ExtractRolesTest(TestCase):

    def test_extract_roles(self):
        claims = {
            'realm_access': {'roles': ['realm-role']},
            'resource_access': {'netbox': {'roles': ['client-role']}, 'other': {'roles': ['foreign']}},
            'groups': ['/netbox/admins'],
        }
        self.assertEqual(
            extract_roles(claims, 'netbox', ['realm', 'client', 'groups']),
            {'realm-role', 'client-role', '/netbox/admins', 'admins'},
        )
        self.assertEqual(extract_roles(claims, 'netbox', ['client']), {'client-role'})
        self.assertEqual(extract_roles({}, 'netbox', ['realm', 'client', 'groups']), set())


class PipelineTest(TestCase):

    def test_build_pipeline(self):
        pipeline = build_pipeline(settings.SOCIAL_AUTH_PIPELINE)
        # The access check must run before the user is looked up or created
        self.assertLess(pipeline.index(CHECK_ACCESS), pipeline.index('social_core.pipeline.social_auth.social_user'))
        self.assertLess(pipeline.index(CHECK_ACCESS), pipeline.index('social_core.pipeline.user.create_user'))
        self.assertEqual(pipeline[-2:], (SYNC_ROLES, REMEMBER_TOKENS))
        # Idempotent
        self.assertEqual(build_pipeline(pipeline), pipeline)

    def test_pipeline_installed(self):
        self.assertEqual(settings.SOCIAL_AUTH_KEYCLOAK_OIDC_PIPELINE, build_pipeline(settings.SOCIAL_AUTH_PIPELINE))


class LoginTest(KeycloakTestCase):

    def test_login_button(self):
        response = self.client.get(reverse('login'))
        self.assertContains(response, begin_url())
        self.assertContains(response, 'Keycloak')

    def test_authorization_request(self):
        response = self.begin()
        url = urlparse(response['Location'])
        query = {k: v[0] for k, v in parse_qs(url.query).items()}
        self.assertEqual(f'{url.scheme}://{url.netloc}{url.path}', f'{ISSUER}/protocol/openid-connect/auth')
        self.assertEqual(query['response_type'], 'code')
        self.assertEqual(query['client_id'], 'netbox')
        self.assertEqual(query['redirect_uri'], 'http://testserver/oauth/complete/keycloak-oidc/')
        self.assertIn('openid', query['scope'].split())
        self.assertTrue(query['state'])
        self.assertTrue(query['nonce'])
        self.assertEqual(query['code_challenge_method'], 'S256')

    def test_login_creates_user(self):
        self.keycloak.add_user('alice', email='alice@example.com')
        response = self.login('alice')
        self.assertRedirects(response, settings.LOGIN_REDIRECT_URL, fetch_redirect_response=False)
        self.assertLoggedIn('alice')

        user = User.objects.get(username='alice')
        self.assertEqual(user.email, 'alice@example.com')
        self.assertEqual(user.first_name, 'Alice')
        self.assertFalse(user.is_superuser)
        social = user.social_auth.get()
        self.assertEqual(social.provider, 'keycloak-oidc')
        self.assertEqual(social.uid, self.keycloak.users['alice']['sub'])

        session = self.client.session
        self.assertIn(session[SESSION_REFRESH_TOKEN], self.keycloak.refresh_tokens)
        self.assertTrue(session[SESSION_ID_TOKEN])
        self.assertEqual(session[SESSION_SUBJECT], self.keycloak.users['alice']['sub'])
        self.assertAlmostEqual(session[SESSION_LAST_CHECK], time.time(), delta=10)

    def test_second_login_reuses_user(self):
        self.keycloak.add_user('alice')
        self.login('alice')
        self.client.logout()
        self.login('alice')
        self.assertLoggedIn('alice')
        self.assertEqual(User.objects.filter(username='alice').count(), 1)

    def test_invalid_id_token_signature(self):
        self.keycloak.add_user('mallory')
        self.keycloak.signing_key = generate_key()
        self.login('mallory')
        self.assertLoggedOut()
        self.assertFalse(User.objects.filter(username='mallory').exists())

    def test_invalid_id_token_audience(self):
        self.keycloak.add_user('mallory')
        self.keycloak.id_token_overrides = {'aud': 'another-client', 'azp': 'another-client'}
        self.login('mallory')
        self.assertLoggedOut()

    def test_invalid_id_token_issuer(self):
        self.keycloak.add_user('mallory')
        self.keycloak.id_token_overrides = {'iss': 'https://evil.test/realms/netbox'}
        self.login('mallory')
        self.assertLoggedOut()

    def test_expired_id_token(self):
        self.keycloak.add_user('mallory')
        self.keycloak.id_token_overrides = {'exp': int(time.time()) - 60}
        self.login('mallory')
        self.assertLoggedOut()

    def test_invalid_nonce(self):
        self.keycloak.add_user('mallory')
        self.keycloak.id_token_overrides = {'nonce': 'replayed'}
        self.login('mallory')
        self.assertLoggedOut()

    def test_invalid_state(self):
        self.keycloak.add_user('mallory')
        response = self.begin()
        params = self.keycloak.authorize(response['Location'], 'mallory')
        params['state'] = 'forged'
        self.client.get(reverse('social:complete', args=['keycloak-oidc']), params)
        self.assertLoggedOut()

    def test_pkce_verifier_required(self):
        self.keycloak.add_user('mallory')
        response = self.begin()
        params = self.keycloak.authorize(response['Location'], 'mallory')
        self.keycloak.codes[params['code']]['code_challenge'] = 'something-else'
        self.client.get(reverse('social:complete', args=['keycloak-oidc']), params)
        self.assertLoggedOut()

    def test_keycloak_error_redirects_to_login(self):
        response = self.begin()
        state = parse_qs(urlparse(response['Location']).query)['state'][0]
        response = self.client.get(
            reverse('social:complete', args=['keycloak-oidc']), {'error': 'access_denied', 'state': state}
        )
        self.assertRedirects(response, settings.LOGIN_URL, fetch_redirect_response=False)
        self.assertLoggedOut()


class AccessControlTest(KeycloakTestCase):

    @plugin_config(required_roles=['netbox-user'])
    def test_required_role_missing(self):
        self.keycloak.add_user('bob', realm_roles=['offline_access'])
        response = self.login('bob')
        self.assertRedirects(response, settings.LOGIN_URL, fetch_redirect_response=False)
        self.assertLoggedOut()
        # No account is created for users without access
        self.assertFalse(User.objects.filter(username='bob').exists())

    @plugin_config(required_roles=['netbox-user'])
    def test_required_role_present(self):
        self.keycloak.add_user('bob', client_roles=['netbox-user'])
        self.login('bob')
        self.assertLoggedIn('bob')

    @plugin_config(required_roles=['netbox-user'], role_sources=['realm'])
    def test_role_sources(self):
        self.keycloak.add_user('bob', client_roles=['netbox-user'])
        self.login('bob')
        self.assertLoggedOut()

    @plugin_config(superuser_roles=['netbox-admin'])
    def test_superuser_role(self):
        self.keycloak.add_user('carol', realm_roles=['netbox-admin'])
        self.login('carol')
        self.assertTrue(User.objects.get(username='carol').is_superuser)

        # Revoking the role revokes superuser status on the next login
        self.client.logout()
        self.keycloak.users['carol']['realm_roles'] = []
        self.login('carol')
        self.assertFalse(User.objects.get(username='carol').is_superuser)

    def test_superuser_untouched_without_superuser_roles(self):
        self.keycloak.add_user('carol')
        self.login('carol')
        User.objects.filter(username='carol').update(is_superuser=True)
        self.client.logout()
        self.login('carol')
        self.assertTrue(User.objects.get(username='carol').is_superuser)

    @plugin_config(group_mapping={'netbox-admins': ['Admins', 'Operators'], 'ops': 'Operators', 'x': 'Missing'})
    def test_group_mapping(self):
        Group.objects.create(name='Admins')
        Group.objects.create(name='Operators')
        unmanaged = Group.objects.create(name='Unmanaged')
        self.keycloak.add_user('dave', groups=['/netbox-admins'], realm_roles=['x'])
        self.login('dave')
        user = User.objects.get(username='dave')
        self.assertEqual(set(user.groups.values_list('name', flat=True)), {'Admins', 'Operators'})
        self.assertFalse(Group.objects.filter(name='Missing').exists())

        # Losing a role removes the mapped groups, unmanaged groups are kept
        user.groups.add(unmanaged)
        self.client.logout()
        self.keycloak.users['dave']['groups'] = []
        self.keycloak.users['dave']['realm_roles'] = ['ops']
        self.login('dave')
        self.assertEqual(set(user.groups.values_list('name', flat=True)), {'Operators', 'Unmanaged'})

    @plugin_config(group_mapping={'ops': ['Operators']}, auto_create_groups=True)
    def test_group_auto_create(self):
        self.keycloak.add_user('erin', realm_roles=['ops'])
        self.login('erin')
        self.assertTrue(User.objects.get(username='erin').groups.filter(name='Operators').exists())

    @plugin_config(group_mapping={'ops': ['Operators']}, remove_unmapped_groups=False)
    def test_keep_unmapped_groups(self):
        operators = Group.objects.create(name='Operators')
        self.keycloak.add_user('erin')
        self.login('erin')
        user = User.objects.get(username='erin')
        user.groups.add(operators)
        self.client.logout()
        self.login('erin')
        self.assertTrue(user.groups.filter(name='Operators').exists())
