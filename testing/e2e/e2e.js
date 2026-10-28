// End-to-end test: NetBox + netbox_keycloak_oidc against a real Keycloak 26 instance
const { chromium } = require('playwright');
const NB = 'http://localhost:8000';
const KC = 'http://localhost:8080';

let failures = 0;
function check(name, cond, extra = '') {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? '  (' + extra + ')' : ''}`);
  if (!cond) failures++;
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
  return r.status === 204 || r.status === 201 ? null : r.json();
}
const userId = async u => (await admin(`/users?username=${u}&exact=true`))[0].id;

async function login(page, username, expectForm = true) {
  await page.goto(`${NB}/login/`);
  await page.getByText('Keycloak', { exact: false }).last().click();
  if (expectForm) {
    await page.waitForURL(/localhost:8080/);
    await page.fill('#username', username);
    await page.fill('#password', `Passw0rd-${username}`);
    await page.click('#kc-login');
  }
  await page.waitForURL(u => u.toString().startsWith(NB));
  await page.waitForLoadState('networkidle');
}
const loggedInAs = async page => {
  const r = await page.request.get(`${NB}/api/users/config/`);
  return r.ok() ? 'yes' : 'no';
};

(async () => {
  // Reset state from earlier runs
  const cl = (await admin('/clients?clientId=netbox'))[0];
  const userRole = await admin(`/clients/${cl.id}/roles/netbox-user`);
  await admin(`/users/${await userId('dave')}/role-mappings/clients/${cl.id}`, 'POST', [userRole]);
  for (const u of ['alice', 'bob', 'carol', 'dave']) await admin(`/users/${await userId(u)}/logout`, 'POST');

  const browser = await chromium.launch();
  const ctx = async () => (await browser.newContext()).newPage();

  // 1. Regular user with role netbox-user
  let alice = await ctx();
  await alice.goto(`${NB}/login/`);
  check('login page shows Keycloak button', await alice.getByText('Keycloak').count() > 0);
  await login(alice, 'alice');
  check('alice logged in', (await loggedInAs(alice)) === 'yes', alice.url());
  check('alice lands on NetBox home', alice.url() === `${NB}/`, alice.url());
  const status = await alice.goto(`${NB}/plugins/keycloak-oidc/status/`);
  check('alice (no superuser) cannot open status page', status.status() === 403, String(status.status()));

  // 2. User without any NetBox role
  const bob = await ctx();
  await login(bob, 'bob');
  check('bob without role is denied', (await loggedInAs(bob)) === 'no');
  check('bob sent back to login page', bob.url().startsWith(`${NB}/login/`), bob.url());
  check('bob sees error message', (await bob.content()).includes('Login via Keycloak failed'));

  // 3. Admin role -> superuser, diagnostics page
  const carol = await ctx();
  await login(carol, 'carol');
  check('carol logged in', (await loggedInAs(carol)) === 'yes');
  const st = await carol.goto(`${NB}/plugins/keycloak-oidc/status/`);
  const html = await carol.content();
  check('carol (superuser) opens status page', st.status() === 200, String(st.status()));
  check('status page reports healthy connection', html.includes('Keycloak connection OK'));
  check('status page: no failed checks', !html.includes('>Failed<'));

  // 4. Single logout: NetBox logout ends Keycloak SSO session
  await carol.goto(`${NB}/logout/`);
  await carol.waitForLoadState('networkidle');
  check('carol logged out of NetBox', (await loggedInAs(carol)) === 'no', carol.url());
  check('carol redirected back to NetBox after Keycloak logout', carol.url().startsWith(NB), carol.url());
  const sessions = await admin(`/users/${await userId('carol')}/sessions`);
  check('carol has no Keycloak session left', sessions.length === 0, `${sessions.length} sessions`);
  await carol.goto(`${NB}/login/`);
  await carol.getByText('Keycloak').last().click();
  await carol.waitForURL(/localhost:8080/);
  check('next login requires password again', await carol.locator('#password').count() === 1);

  // 5. Session ended in Keycloak (admin "sign out") -> NetBox session terminated
  await alice.goto(`${NB}/dcim/sites/`);  // re-validates (interval elapsed) and resets the timer
  check('alice still logged in after re-validation', (await loggedInAs(alice)) === 'yes');
  await admin(`/users/${await userId('alice')}/logout`, 'POST');
  await alice.goto(`${NB}/`);
  check('alice still logged in within check interval', (await loggedInAs(alice)) === 'yes');
  await new Promise(r => setTimeout(r, 6000));
  await alice.goto(`${NB}/dcim/sites/`);
  check('alice logged out after Keycloak session ended', (await loggedInAs(alice)) === 'no', alice.url());
  check('alice redirected to login', alice.url().startsWith(`${NB}/login/`), alice.url());
  check('alice sees session-ended message', (await alice.content()).includes('Keycloak session has ended'));

  // 6. Role revoked in Keycloak while logged in
  const dave = await ctx();
  await login(dave, 'dave');
  check('dave logged in', (await loggedInAs(dave)) === 'yes');
  const clients = await admin('/clients?clientId=netbox');
  const role = await admin(`/clients/${clients[0].id}/roles/netbox-user`);
  await admin(`/users/${await userId('dave')}/role-mappings/clients/${clients[0].id}`, 'DELETE', [role]);
  await new Promise(r => setTimeout(r, 6000));
  await dave.goto(`${NB}/`);
  check('dave logged out after role revocation', (await loggedInAs(dave)) === 'no', dave.url());
  await login(dave, 'dave', false);  // SSO session still alive in Keycloak
  check('dave cannot log in again without role', (await loggedInAs(dave)) === 'no', dave.url());

  // 7. Session stays valid while Keycloak session is alive
  const alice2 = await ctx();
  await login(alice2, 'alice');
  await new Promise(r => setTimeout(r, 6000));
  await alice2.goto(`${NB}/dcim/sites/`);
  check('alice stays logged in across a successful re-validation', (await loggedInAs(alice2)) === 'yes', alice2.url());

  await browser.close();
  console.log(failures ? `\n${failures} FAILED` : '\nALL PASSED');
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); process.exit(2); });
