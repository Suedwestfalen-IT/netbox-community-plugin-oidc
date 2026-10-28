#!/usr/bin/env bash
# Creates the realm "netbox" used by the end-to-end test in a local Keycloak started with
#   KC_BOOTSTRAP_ADMIN_USERNAME=admin KC_BOOTSTRAP_ADMIN_PASSWORD=admin bin/kc.sh start-dev --http-port 8080
# Usage: KCADM=/path/to/keycloak/bin/kcadm.sh ./setup_keycloak.sh
set -euo pipefail
K=${KCADM:-kcadm.sh}
NETBOX=${NETBOX_URL:-http://localhost:8000}

$K config credentials --server "${KEYCLOAK_URL:-http://localhost:8080}" --realm master --user admin --password admin
$K create realms -s realm=netbox -s enabled=true
CID=$($K create clients -r netbox -i -s clientId=netbox -s enabled=true -s publicClient=false \
  -s standardFlowEnabled=true -s directAccessGrantsEnabled=false -s secret=netbox-secret \
  -s "redirectUris=[\"$NETBOX/oauth/complete/keycloak-oidc/\"]" \
  -s "attributes={\"post.logout.redirect.uris\":\"$NETBOX/*\",\"pkce.code.challenge.method\":\"S256\"}")
$K create "clients/$CID/protocol-mappers/models" -r netbox -s name=groups -s protocol=openid-connect \
  -s protocolMapper=oidc-group-membership-mapper \
  -s 'config={"claim.name":"groups","full.path":"true","access.token.claim":"true","id.token.claim":"false","userinfo.token.claim":"false"}'
$K create "clients/$CID/roles" -r netbox -s name=netbox-user
$K create "clients/$CID/roles" -r netbox -s name=netbox-admin
GID=$($K create groups -r netbox -i -s name=netbox-operators)

# alice: netbox-user | bob: no role | carol: netbox-admin | dave: netbox-user + group netbox-operators
for u in alice bob carol dave; do
  $K create users -r netbox -s username=$u -s enabled=true -s email=$u@example.com -s emailVerified=true \
    -s firstName=${u^} -s lastName=Test
  $K set-password -r netbox --username $u --new-password "Passw0rd-$u"
done
$K add-roles -r netbox --uusername alice --cclientid netbox --rolename netbox-user
$K add-roles -r netbox --uusername carol --cclientid netbox --rolename netbox-admin
$K add-roles -r netbox --uusername dave --cclientid netbox --rolename netbox-user
DAVE=$($K get users -r netbox -q username=dave -q exact=true --fields id --format csv --noquotes)
$K update "users/$DAVE/groups/$GID" -r netbox -s realm=netbox -s userId="$DAVE" -s groupId="$GID" -n
# Groups for the group sync (sync_groups_prefix 'nb-')
NBOPS=$($K create groups -r netbox -i -s name=nb-dc-ops)
$K create groups -r netbox -s name=nb-empty
OTHER=$($K create groups -r netbox -i -s name=other-team)
ALICE=$($K get users -r netbox -q username=alice -q exact=true --fields id --format csv --noquotes)
$K update "users/$ALICE/groups/$NBOPS" -r netbox -s realm=netbox -s userId="$ALICE" -s groupId="$NBOPS" -n
$K update "users/$ALICE/groups/$OTHER" -r netbox -s realm=netbox -s userId="$ALICE" -s groupId="$OTHER" -n
$K update "users/$DAVE/groups/$NBOPS" -r netbox -s realm=netbox -s userId="$DAVE" -s groupId="$NBOPS" -n

# SCIM (Keycloak >= 26.8): enable the API and create a read-only service account client
if $K update realms/netbox -s scimApiEnabled=true; then
  SC=$($K create clients -r netbox -i -s clientId=netbox-scim -s enabled=true -s publicClient=false \
    -s standardFlowEnabled=false -s directAccessGrantsEnabled=false -s serviceAccountsEnabled=true \
    -s fullScopeAllowed=false -s secret=scim-secret)
  $K create "clients/$SC/protocol-mappers/models" -r netbox -s name=scim-audience -s protocol=openid-connect \
    -s protocolMapper=oidc-audience-mapper \
    -s "config={\"included.custom.audience\":\"${KEYCLOAK_URL:-http://localhost:8080}/realms/netbox/scim/v2\",\"access.token.claim\":\"true\",\"id.token.claim\":\"false\"}"
  RM=$($K get clients -r netbox -q clientId=realm-management --fields id --format csv --noquotes)
  ROLES=$($K get "clients/$RM/roles" -r netbox | python3 -c \
    "import json,sys; print(json.dumps([r for r in json.load(sys.stdin) if r['name'] in ('view-users','query-users','query-groups')]))")
  $K create "clients/$SC/scope-mappings/clients/$RM" -r netbox -b "$ROLES"
  $K add-roles -r netbox --uusername service-account-netbox-scim --cclientid realm-management \
    --rolename view-users --rolename query-users --rolename query-groups
  echo "SCIM enabled"
else
  echo "SCIM API not available (requires Keycloak 26.8 or later)"
fi
echo "Realm netbox ready"
