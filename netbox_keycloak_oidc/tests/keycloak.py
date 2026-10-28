"""
A minimal in-process imitation of a Keycloak realm, used to exercise the complete OIDC login flow without
network access. Outgoing HTTP requests of python-social-auth are routed to FakeKeycloak.handle().
"""
import base64
import hashlib
import json
import time
import uuid
from contextlib import contextmanager
from unittest import mock
from urllib.parse import parse_qs, urlparse

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = 'https://keycloak.test/realms/netbox'
CLIENT_ID = 'netbox'
CLIENT_SECRET = 'secret'


def generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeKeycloak:

    def __init__(self):
        self.key = generate_key()
        # A fresh key ID per instance makes the backend reload its cached JWKS
        self.kid = uuid.uuid4().hex
        self.users = {}
        self.codes = {}
        self.refresh_tokens = {}
        self.requests = []
        self.reachable = True
        # Overrides for the next issued tokens (e.g. to tamper with claims)
        self.id_token_overrides = {}
        self.signing_key = None

    # Users

    def add_user(self, username, realm_roles=(), client_roles=(), groups=(), email=None):
        sub = str(uuid.uuid4())
        self.users[username] = {
            'sub': sub,
            'preferred_username': username,
            'email': email or f'{username}@example.com',
            'given_name': username.capitalize(),
            'family_name': 'Test',
            'realm_roles': list(realm_roles),
            'client_roles': list(client_roles),
            'groups': list(groups),
            'enabled': True,
        }
        return self.users[username]

    # Endpoints

    @property
    def discovery(self):
        base = f'{ISSUER}/protocol/openid-connect'
        return {
            'issuer': ISSUER,
            'authorization_endpoint': f'{base}/auth',
            'token_endpoint': f'{base}/token',
            'userinfo_endpoint': f'{base}/userinfo',
            'jwks_uri': f'{base}/certs',
            'end_session_endpoint': f'{base}/logout',
            'revocation_endpoint': f'{base}/revoke',
            'code_challenge_methods_supported': ['plain', 'S256'],
            'token_endpoint_auth_methods_supported': ['client_secret_basic', 'client_secret_post'],
        }

    @property
    def jwks(self):
        public = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        return {'keys': [{**public, 'kid': self.kid, 'use': 'sig', 'alg': 'RS256'}]}

    def authorize(self, authorization_url, username):
        """
        Simulate the user logging in at Keycloak; returns the callback query parameters.
        """
        query = {k: v[0] for k, v in parse_qs(urlparse(authorization_url).query).items()}
        assert query['client_id'] == CLIENT_ID
        code = uuid.uuid4().hex
        self.codes[code] = {
            'username': username,
            'nonce': query.get('nonce'),
            'redirect_uri': query['redirect_uri'],
            'code_challenge': query.get('code_challenge'),
            'code_challenge_method': query.get('code_challenge_method'),
        }
        return {'code': code, 'state': query['state']}

    def sign(self, claims, key=None):
        return jwt.encode(claims, key or self.signing_key or self.key, algorithm='RS256', headers={'kid': self.kid})

    def issue_tokens(self, username, nonce=None):
        user = self.users[username]
        now = int(time.time())
        access_token = self.sign({
            'iss': ISSUER, 'sub': user['sub'], 'aud': 'account', 'azp': CLIENT_ID, 'typ': 'Bearer',
            'exp': now + 300, 'iat': now,
            'realm_access': {'roles': user['realm_roles']},
            'resource_access': {CLIENT_ID: {'roles': user['client_roles']}},
            'groups': user['groups'],
            'preferred_username': username,
        })
        id_claims = {
            'iss': ISSUER, 'sub': user['sub'], 'aud': CLIENT_ID, 'azp': CLIENT_ID, 'typ': 'ID',
            'exp': now + 300, 'iat': now, 'auth_time': now,
            'preferred_username': username, 'email': user['email'],
        }
        if nonce:
            id_claims['nonce'] = nonce
        id_claims.update(self.id_token_overrides)
        refresh_token = uuid.uuid4().hex
        self.refresh_tokens[refresh_token] = {'username': username, 'nonce': nonce}
        return {
            'access_token': access_token,
            'id_token': self.sign(id_claims),
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': 300,
            'scope': 'openid profile email',
        }

    def token(self, data, auth):
        client_id, client_secret = auth or (data.get('client_id'), data.get('client_secret'))
        if (client_id, client_secret) != (CLIENT_ID, CLIENT_SECRET):
            return 401, {'error': 'invalid_client'}
        if data['grant_type'] == 'authorization_code':
            grant = self.codes.pop(data['code'], None)
            if grant is None or grant['redirect_uri'] != data.get('redirect_uri'):
                return 400, {'error': 'invalid_grant'}
            if grant['code_challenge']:
                digest = hashlib.sha256(data.get('code_verifier', '').encode()).digest()
                if base64.urlsafe_b64encode(digest).rstrip(b'=').decode() != grant['code_challenge']:
                    return 400, {'error': 'invalid_grant', 'error_description': 'PKCE verification failed'}
            return 200, self.issue_tokens(grant['username'], grant['nonce'])
        if data['grant_type'] == 'refresh_token':
            grant = self.refresh_tokens.pop(data['refresh_token'], None)
            if grant is None or not self.users[grant['username']]['enabled']:
                return 400, {'error': 'invalid_grant', 'error_description': 'Session not active'}
            return 200, self.issue_tokens(grant['username'], grant['nonce'])
        return 400, {'error': 'unsupported_grant_type'}

    def userinfo(self, headers):
        token = headers.get('Authorization', '').removeprefix('Bearer ')
        claims = jwt.decode(token, self.key.public_key(), algorithms=['RS256'], options={'verify_aud': False})
        user = next(u for u in self.users.values() if u['sub'] == claims['sub'])
        return 200, {k: user[k] for k in ('sub', 'preferred_username', 'email', 'given_name', 'family_name')}

    def end_session(self):
        for username in list(self.users):
            self.end_sessions_of(username)

    def end_sessions_of(self, username):
        self.refresh_tokens = {k: v for k, v in self.refresh_tokens.items() if v['username'] != username}

    # HTTP routing

    def handle(self, method, url, headers=None, data=None, auth=None, **kwargs):
        self.requests.append((method, url))
        if not self.reachable:
            raise requests.ConnectionError('Connection refused')
        endpoints = self.discovery
        path = url.split('?')[0]
        if path == f'{ISSUER}/.well-known/openid-configuration':
            status, body = 200, endpoints
        elif path == endpoints['jwks_uri']:
            status, body = 200, self.jwks
        elif path == endpoints['token_endpoint']:
            status, body = self.token(data or {}, auth)
        elif path == endpoints['userinfo_endpoint']:
            status, body = self.userinfo(headers or {})
        else:
            status, body = 404, {'error': 'not found'}
        response = requests.Response()
        response.status_code = status
        response._content = json.dumps(body).encode()
        response.headers['Content-Type'] = 'application/json'
        response.url = url
        return response

    @contextmanager
    def running(self):
        with mock.patch('social_core.backends.base.requests.request', side_effect=self.handle):
            yield self

    def requests_to(self, endpoint):
        return [r for r in self.requests if r[1].split('?')[0] == self.discovery[endpoint]]
