// End-to-end test of SCIM provisioning and group sync against a real Keycloak (>= 26.8).
// Requires the realm from setup_keycloak.sh, a fresh NetBox database and NetBox running on port 8000
// with testing/e2e/configuration.py. Set NETBOX_DIR (the netbox/ directory) and PYTHON (NetBox venv python).
const { execFileSync } = require('child_process');
const { chromium } = require('playwright');

const NB = 'http://localhost:8000';
const KC = 'http://localhost:8080';
const NETBOX_DIR = process.env.NETBOX_DIR || '/opt/netbox/netbox';
const PYTHON = process.env.PYTHON || 'python3';

let failures = 0;
function check(name, cond, extra = '') {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? '  (' + extra + ')' : ''}`);
  if (!cond) failures++;
}

function manage(...args) {
  return execFileSync(PYTHON, ['manage.py', ...args], { cwd: NETBOX_DIR, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}
const sync = () => manage('keycloak_scim_sync');

// NetBox state of all users: {username: {id, active, superuser, email, last_name, groups, uid}}
function netboxUsers() {
  const code = `
import json
from users.models import User
print('JSON' + json.dumps({u.username: {
    'id': u.pk, 'active': u.is_active, 'superuser': u.is_superuser, 'email': u.email, 'last_name': u.last_name,
    'groups': sorted(u.groups.values_list('name', flat=True)),
    'uid': next(iter(u.social_auth.filter(provider='keycloak-oidc').values_list('uid', flat=True)), None),
} for u in User.objects.all()}))`;
  const out = manage('shell', '-c', code);
  return JSON.parse(out.slice(out.indexOf('JSON') + 4));
}
function netboxGroups() {
  const out = manage('shell', '-c', "from users.models import Group; print('JSON' + str(sorted(Group.objects.values_list('name', flat=True))).replace(\"'\", '\"'))");
  return JSON.parse(out.slice(out.indexOf('JSON') + 4));
}

async function admin(path, method = 'GET', body) {
  const t = await fetch(`${KC}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username: 'admin', password: 'admin' }),
  }).then(r => r.json());
  const r = await fetch(`${KC}/admin/realms/netbox${path}`, {
    method,
    headers: { Authorization: `Bearer ${t.access_token}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (r.status >= 400) throw new Error(`${method} ${path}: HTTP ${r.status} ${await r.text()}`);
  return r.status === 204 || r.status === 201 ? r.headers.get('location') : r.json();
}
const userId = async u => (await admin(`/users?username=${u}&exact=true`))[0].id;
const groupId = async g => (await admin(`/groups?search=${g}&exact=true`))[0].id;

async function login(page, username) {
  await page.goto(`${NB}/login/`);
  await page.getByText('Keycloak').last().click();
  await page.waitForURL(/localhost:8080/);
  await page.fill('#username', username);
  await page.fill('#password', `Passw0rd-${username}`);
  await page.click('#kc-login');
  await page.waitForURL(u => u.toString().startsWith(NB));
  await page.waitForLoadState('networkidle');
}
const loggedIn = async page => (await page.request.get(`${NB}/api/users/config/`)).ok();

(async () => {
  // 1. Initial provisioning, before anybody logged in
  let out = sync();
  let users = netboxUsers();
  check('sync creates all realm users', ['alice', 'bob', 'carol', 'dave'].every(u => u in users), Object.keys(users).join(','));
  check('users are linked to their Keycloak ID', users.alice.uid === await userId('alice'));
  check('email and names are provisioned', users.alice.email === 'alice@example.com' && users.alice.last_name === 'Test');
  let groups = netboxGroups();
  check('prefixed Keycloak groups are created (also without members)', groups.includes('nb-dc-ops') && groups.includes('nb-empty'), groups.join(','));
  check('groups without the prefix are not created', !groups.includes('other-team') && !groups.includes('netbox-operators'));
  check('group memberships are synced', users.alice.groups.includes('nb-dc-ops') && users.dave.groups.includes('nb-dc-ops'),
        JSON.stringify([users.alice.groups, users.dave.groups]));
  check('group_mapping applied via SCIM', users.dave.groups.includes('Operators'), users.dave.groups.join(','));

  // 2. Login uses the provisioned account
  const browser = await chromium.launch();
  const alice = await (await browser.newContext()).newPage();
  await login(alice, 'alice');
  users = netboxUsers();
  check('alice can log in', await loggedIn(alice));
  check('login uses the provisioned user (no duplicate, no suffix)',
        Object.keys(users).filter(u => u.startsWith('alice')).length === 1 && users.alice.id !== undefined);
  check('login applies role mapping to provisioned user', users.alice.groups.includes('Readers'), users.alice.groups.join(','));
  check('login keeps synced groups', users.alice.groups.includes('nb-dc-ops'));

  // 3. Changes in Keycloak are synced
  const carolId = await userId('carol');
  await admin(`/users/${carolId}`, 'PUT', { lastName: 'Renamed', email: 'carol.new@example.com' });
  await admin(`/users/${await userId('dave')}/groups/${await groupId('nb-dc-ops')}`, 'DELETE');
  await admin('/users', 'POST', { username: 'erin', enabled: true, email: 'erin@example.com', firstName: 'Erin', lastName: 'Test' });
  await admin('/groups', 'POST', { name: 'nb-new-team' });
  await admin(`/users/${await userId('erin')}/groups/${await groupId('nb-new-team')}`, 'PUT');
  sync();
  users = netboxUsers();
  check('changed name and email are synced', users.carol.last_name === 'Renamed' && users.carol.email === 'carol.new@example.com');
  check('removal from a Keycloak group is synced', !users.dave.groups.includes('nb-dc-ops') && users.dave.groups.includes('Operators'),
        users.dave.groups.join(','));
  check('new Keycloak user is created', users.erin && users.erin.active);
  check('new Keycloak group is created with its members', users.erin && users.erin.groups.includes('nb-new-team'));

  // 4. Disable / enable in Keycloak; API token of a disabled user stops working
  const tokenOut = manage('shell', '-c',
    "from users.models import Token, User; t = Token(user=User.objects.get(username='bob')); t.full_clean(); t.save(); " +
    "print('TOKEN' + (t.get_auth_header_prefix() + t.token if hasattr(t, 'get_auth_header_prefix') else 'Token ' + t.key))");
  const authHeader = tokenOut.slice(tokenOut.indexOf('TOKEN') + 5).trim();
  const apiStatus = async () => (await fetch(`${NB}/api/users/config/`, { headers: { Authorization: authHeader } })).status;
  check('bob\'s API token works', (await apiStatus()) === 200, String(await apiStatus()));
  const bobId = await userId('bob');
  await admin(`/users/${bobId}`, 'PUT', { enabled: false });
  out = sync();
  check('user disabled in Keycloak is deactivated', netboxUsers().bob.active === false, out.trim().split('\n').pop());
  check('API token of deactivated user is rejected', (await apiStatus()) === 403, String(await apiStatus()));
  await admin(`/users/${bobId}`, 'PUT', { enabled: true });
  sync();
  check('user enabled again is reactivated', netboxUsers().bob.active === true);

  // 5. Deleted in Keycloak while logged in: deactivated and session ends immediately
  await admin(`/users/${await userId('alice')}`, 'DELETE');
  sync();
  check('user deleted in Keycloak is deactivated', netboxUsers().alice.active === false);
  await alice.goto(`${NB}/dcim/sites/`);
  check('session of deleted user ends at once', !(await loggedIn(alice)) && alice.url().startsWith(`${NB}/login/`), alice.url());

  // 6. Realm administrators are only exposed minimally by Keycloak and are skipped
  await admin('/users', 'POST', { username: 'frank', enabled: true, email: 'frank@example.com' });
  const rm = (await admin('/clients?clientId=realm-management'))[0];
  const manageUsers = await admin(`/clients/${rm.id}/roles/manage-users`);
  await admin(`/users/${await userId('frank')}/role-mappings/clients/${rm.id}`, 'POST', [manageUsers]);
  out = sync();
  check('realm admin users are skipped', !('frank' in netboxUsers()) && out.includes('Skipping frank'));

  // 7. Existing local users with the same name are not taken over
  manage('shell', '-c', "from users.models import User; User.objects.create_user(username='grace', password='Local-Passw0rd!')");
  await admin('/users', 'POST', { username: 'grace', enabled: true, email: 'grace@example.com' });
  out = sync();
  users = netboxUsers();
  check('local user with the same name is not linked', users.grace.uid === null && out.includes('Skipping grace'));

  await browser.close();
  console.log(failures ? `\n${failures} FAILED` : '\nALL PASSED');
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
