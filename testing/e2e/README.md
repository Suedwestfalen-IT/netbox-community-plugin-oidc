# End-to-end test against a real Keycloak

Runs the complete browser login flow with Playwright: login, denied login without role, superuser
mapping, status page, single logout, session termination after a Keycloak logout and after a role is
revoked.

1. Start Keycloak (tested with 26.4):

   ```bash
   KC_BOOTSTRAP_ADMIN_USERNAME=admin KC_BOOTSTRAP_ADMIN_PASSWORD=admin bin/kc.sh start-dev --http-port 8080
   ```

2. Create the test realm: `KCADM=/path/to/keycloak/bin/kcadm.sh ./setup_keycloak.sh`

3. Start NetBox with this configuration (database `netbox_e2e` must exist):

   ```bash
   cd /path/to/netbox/netbox
   export NETBOX_CONFIGURATION=testing.e2e.configuration PYTHONPATH=/path/to/netbox-community-plugin-oidc
   python manage.py migrate
   python manage.py keycloak_oidc_check
   python manage.py runserver 0.0.0.0:8000 --insecure
   ```

4. Run the test (needs the `playwright` npm package with Chromium): `node e2e.js`
