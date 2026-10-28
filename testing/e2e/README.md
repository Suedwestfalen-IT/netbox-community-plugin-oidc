# End-to-end test against a real Keycloak

Runs the complete browser login flow with Playwright: login, denied login without role, superuser
mapping, status page, single logout, session termination after a Keycloak logout and after a role is
revoked.

1. Start Keycloak (tested with 26.4.2 and 26.8.1; SCIM requires 26.8):

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

4. Run the tests (they need the `playwright` npm package with Chromium):

   ```bash
   node e2e.js       # login, roles, session validation, logout
   NETBOX_DIR=/path/to/netbox/netbox PYTHON=/path/to/venv/bin/python node e2e_scim.js   # SCIM + group sync
   ```

   `e2e_scim.js` needs Keycloak 26.8 or later and a fresh NetBox database. It changes users in the realm,
   so run `setup_keycloak.sh` again (after deleting the realm) before repeating a test. The SCIM
   background job can be checked by running `python manage.py rqworker`. With this configuration it syncs
   every minute.
