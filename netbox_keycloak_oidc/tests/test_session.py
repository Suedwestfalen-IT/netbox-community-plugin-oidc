from urllib.parse import parse_qs, urlparse

from django.conf import settings
from django.urls import reverse
from users.models import User

from netbox_keycloak_oidc.diagnostics import FAILED, OK, run_diagnostics
from netbox_keycloak_oidc.utils import SESSION_LAST_CHECK, SESSION_REFRESH_TOKEN

from .keycloak import CLIENT_ID, ISSUER
from .test_login import KeycloakTestCase, plugin_config


class SessionValidationTest(KeycloakTestCase):

    def setUp(self):
        super().setUp()
        self.keycloak.add_user('alice', realm_roles=['netbox-user'])
        self.login('alice')

    def expire_check(self):
        session = self.client.session
        session[SESSION_LAST_CHECK] = 0
        session.save()

    def refresh_requests(self):
        return len(self.keycloak.requests_to('token_endpoint'))

    def test_no_check_within_interval(self):
        before = self.refresh_requests()
        self.assertEqual(self.client.get(reverse('home')).status_code, 200)
        self.assertEqual(self.refresh_requests(), before)

    def test_session_still_valid(self):
        old_token = self.client.session[SESSION_REFRESH_TOKEN]
        self.expire_check()
        before = self.refresh_requests()
        self.assertEqual(self.client.get(reverse('home')).status_code, 200)
        self.assertEqual(self.refresh_requests(), before + 1)
        # The rotated refresh token is stored
        self.assertNotEqual(self.client.session[SESSION_REFRESH_TOKEN], old_token)
        self.assertIn(self.client.session[SESSION_REFRESH_TOKEN], self.keycloak.refresh_tokens)

    def test_session_ended_in_keycloak(self):
        self.keycloak.end_sessions_of('alice')
        self.expire_check()
        response = self.client.get(reverse('dcim:site_list'))
        self.assertRedirects(
            response, f'{settings.LOGIN_URL}?next={reverse("dcim:site_list")}', fetch_redirect_response=False
        )
        self.assertLoggedOut()

    def test_user_disabled_in_keycloak(self):
        self.keycloak.users['alice']['enabled'] = False
        self.expire_check()
        self.client.get(reverse('home'))
        self.assertLoggedOut()

    @plugin_config(required_roles=['netbox-user'])
    def test_required_role_revoked(self):
        self.expire_check()
        self.client.get(reverse('home'))
        self.assertLoggedIn('alice')

        self.keycloak.users['alice']['realm_roles'] = []
        self.expire_check()
        self.client.get(reverse('home'))
        self.assertLoggedOut()

    def test_htmx_request(self):
        self.keycloak.end_sessions_of('alice')
        self.expire_check()
        response = self.client.get(reverse('home'), headers={'HX-Request': 'true'})
        self.assertTrue(response['HX-Redirect'].startswith(settings.LOGIN_URL))

    def test_api_request(self):
        self.keycloak.end_sessions_of('alice')
        self.expire_check()
        response = self.client.get(reverse('dcim-api:site-list'))
        self.assertEqual(response.status_code, 403)
        self.assertLoggedOut()

    def test_keycloak_unreachable_fail_open(self):
        self.keycloak.reachable = False
        self.expire_check()
        self.assertEqual(self.client.get(reverse('home')).status_code, 200)
        self.assertLoggedIn('alice')

    @plugin_config(session_check_fail_closed=True)
    def test_keycloak_unreachable_fail_closed(self):
        self.keycloak.reachable = False
        self.expire_check()
        self.client.get(reverse('home'))
        self.assertLoggedOut()

    @plugin_config(session_check_interval=0)
    def test_check_disabled(self):
        self.keycloak.end_sessions_of('alice')
        self.expire_check()
        self.client.get(reverse('home'))
        self.assertLoggedIn('alice')

    def test_local_users_unaffected(self):
        self.client.logout()
        user = User.objects.create_user(username='local', password='Pa55word!Pa55word!')
        self.client.force_login(user)
        before = len(self.keycloak.requests)
        self.assertEqual(self.client.get(reverse('home')).status_code, 200)
        self.assertEqual(len(self.keycloak.requests), before)


class LogoutTest(KeycloakTestCase):

    def setUp(self):
        super().setUp()
        self.keycloak.add_user('alice')
        self.login('alice')

    def test_logout_ends_keycloak_session(self):
        id_token = self.client.session['keycloak_oidc_id_token']
        response = self.client.get(reverse('logout'))
        url = urlparse(response['Location'])
        query = {k: v[0] for k, v in parse_qs(url.query).items()}
        self.assertEqual(f'{url.scheme}://{url.netloc}{url.path}', f'{ISSUER}/protocol/openid-connect/logout')
        self.assertEqual(query['client_id'], CLIENT_ID)
        self.assertEqual(query['id_token_hint'], id_token)
        self.assertEqual(query['post_logout_redirect_uri'], 'http://testserver/')
        self.assertLoggedOut()

    @plugin_config(logout_from_keycloak=False)
    def test_local_logout_only(self):
        response = self.client.get(reverse('logout'))
        self.assertEqual(response['Location'], '/')
        self.assertLoggedOut()


class DiagnosticsTest(KeycloakTestCase):

    def test_all_checks_pass(self):
        results = run_diagnostics()
        self.assertEqual([r.name for r in results if r.status != OK], [], results)

    def test_wrong_client_secret(self):
        with self.settings(SOCIAL_AUTH_KEYCLOAK_OIDC_SECRET='wrong'):
            results = {r.name: r for r in run_diagnostics()}
        self.assertEqual(results['Client credentials'].status, FAILED)

    def test_keycloak_unreachable(self):
        self.keycloak.reachable = False
        results = {r.name: r for r in run_diagnostics()}
        self.assertEqual(results['OIDC discovery'].status, FAILED)

    def test_status_view(self):
        user = User.objects.create_user(username='admin', password='x', is_superuser=True)
        self.client.force_login(user)
        response = self.client.get(reverse('plugins:netbox_keycloak_oidc:status'))
        self.assertContains(response, 'Keycloak connection OK')
        self.assertContains(response, 'http://testserver/oauth/complete/keycloak-oidc/')

    def test_status_view_requires_superuser(self):
        self.client.force_login(User.objects.create_user(username='user', password='x'))
        response = self.client.get(reverse('plugins:netbox_keycloak_oidc:status'))
        self.assertEqual(response.status_code, 403)
