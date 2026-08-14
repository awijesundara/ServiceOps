# ServiceOps REST API reference

Version 1.0 · ServiceOps 1.19+

## 1. Scope and base URL

The supported API is REST v1:

```text
https://serviceops.example.com/api/v1
```

The live OpenAPI 3.1 document is available without authentication:

```text
GET /api/v1/openapi.json
```

A human-readable rendering of the same contract is available at:

```text
GET /api/v1/docs
```

The current contract supports ticket discovery, incident creation, controlled
ticket updates, workflow triggering, CMDB auto-registration, and
monitoring-event ingestion. Browser session cookies are not API credentials.

## 2. Create an API client

1. Sign in as a ServiceOps administrator.
2. Open **Administration → API clients**.
3. Select the active user whose permissions the integration will exercise.
4. Select only the required scopes.
5. Create the client and copy the displayed token immediately.

Tokens begin with `sop_` and are displayed once. ServiceOps stores only an
HMAC-derived token verifier. Store the token in a secret manager, never in
source control, shell history, URLs, screenshots, or ordinary log output.

Every request executes as the selected user. A scope does not bypass that
user's tenant, role, team ownership, record visibility, lifecycle approvals,
or field-projection rules. Disabling the user, revoking the client, or moving
the user out of the required team takes effect on subsequent requests.

Available scopes:

| Scope | Purpose |
|---|---|
| `tickets:read` | List and retrieve visible incidents and changes |
| `incidents:create` | Create incidents |
| `tickets:update` | Update an authorized owning-team ticket |
| `workflows:execute` | Trigger configured API workflows for an authorized ticket |
| `cmdb:write` | Idempotent upsert of Configuration Items (§9) |

## 3. Authentication and common headers

Native mobile applications authenticate an actual ServiceOps user rather than
embedding an API-client secret. `POST /api/v1/auth/mobile/login` accepts
`username`, `password`, `provider` (`local` or `ldap`) and optional `mfa_code`;
MFA-enabled accounts require a valid TOTP or backup code. Requests identify the
client with `X-ServiceOps-App-Version`, `X-ServiceOps-App-Build`,
`X-ServiceOps-Platform` and `X-ServiceOps-Device`. Success returns a 15-minute
`som_` access token and rotating 30-day `sor_` refresh token. Store both only in
the platform secure credential store. Refresh through `POST
/api/v1/auth/mobile/refresh` and revoke through `POST
/api/v1/auth/mobile/logout`. Mobile activity is authorized as the signed-in
user and audited with authoritative user and app/device attribution.

Ticket attachment access uses the same bearer identity and `tickets:read`
scope. `GET /api/v1/tickets/{number}/attachments` returns `id`, `fileName`,
`contentType`, `byteSize`, `createdAt`, and an authenticated relative
`downloadURL`. `GET
/api/v1/tickets/{number}/attachments/{attachment_id}/download` streams the
bytes with private/no-store caching. Both calls apply the acting user's normal
ticket visibility and tenant boundary; invisible tickets or attachments return
404. Mobile compatibility aliases exist under `/api/v1/mobile/tickets/...`.

Passkey registration is available to an existing authenticated mobile session:

- `POST /api/v1/auth/passkeys/register/options` issues a five-minute,
  tenant/user-bound WebAuthn creation challenge.
- `POST /api/v1/auth/passkeys/register/complete` verifies the Apple platform
  credential, consumes the challenge once, and stores only the credential ID,
  public key, signature counter, display name and transports.
- `GET /api/v1/auth/passkeys` lists the signed-in user's registered passkeys;
  `DELETE /api/v1/auth/passkeys/{credential_id}` revokes one owned credential
  and records the action in the audit trail.

Passwordless mobile sign-in uses:

- `POST /api/v1/auth/passkeys/authenticate/options` to issue a discoverable
  credential challenge.
- `POST /api/v1/auth/passkeys/authenticate/complete` to verify user presence,
  user verification, origin, relying-party ID, signature and counter, then
  issue the standard mobile access/refresh token pair.

Passkeys fail closed unless `WEBAUTHN_RP_ID` and an HTTPS
`WEBAUTHN_ORIGIN` are configured. Apple clients also require an Associated
Domains `webcredentials:` entitlement matching the relying-party domain and
that domain must serve `/.well-known/apple-app-site-association` containing
the configured `APPLE_PASSKEY_APP_ID`. Plain HTTP LAN development addresses
cannot complete an Apple passkey ceremony.

```http
Authorization: Bearer sop_REDACTED
Accept: application/json
Content-Type: application/json
X-Request-ID: 9acdd549-4938-4eb2-bf8c-175ba8de2adc
```

`X-Request-ID` is optional but recommended. Supply a UUID. ServiceOps returns
the accepted or generated identifier in every response and records it in the
audit chain.

State-changing endpoints also require:

```http
Idempotency-Key: integration-name-operation-unique-value
```

The key must contain 1–128 letters, digits, `.`, `_`, `:`, or `-`. Repeating
the same key, method, path, and body returns the stored response with:

```http
Idempotency-Replayed: true
```

Reusing the key for a different request returns `409 Conflict`.

## 4. List tickets

```http
GET /api/v1/tickets?type=incident&state=In%20Progress&limit=50&cursor=0
Authorization: Bearer sop_REDACTED
```

Required scope: `tickets:read`

Query parameters:

| Parameter | Meaning |
|---|---|
| `type` | Optional: `incident` or `change` |
| `state` | Optional exact state |
| `limit` | 1–100; default 50 |
| `cursor` | Last returned numeric record ID; start at 0 |

```json
{
  "data": [
    {
      "id": 41,
      "number": "INC0000041",
      "type": "incident",
      "title": "Production API unavailable",
      "description": "Health checks are failing.",
      "state": "In Progress",
      "priority": "P1",
      "category": "Application",
      "opened_at": "2026-07-26T12:00:00+00:00",
      "updated_at": "2026-07-26T12:05:00+00:00",
      "internal": {
        "assignment_group": {"id": 1, "name": "CoreApps"},
        "assigned_to": {"id": 18, "name": "Application Engineer"}
      }
    }
  ],
  "meta": {
    "limit": 50,
    "next_cursor": null,
    "request_id": "9acdd549-4938-4eb2-bf8c-175ba8de2adc"
  }
}
```

The `internal` object is returned only to agent, manager, and administrator
audiences. Requester API clients never receive it.

Continue pagination using `next_cursor` until it is `null`. Do not calculate a
cursor from result counts.

## 5. Retrieve one ticket

```http
GET /api/v1/tickets/INC0000041
Authorization: Bearer sop_REDACTED
```

Required scope: `tickets:read`

Ticket numbers are case-insensitive. A record outside the caller's tenant or
visibility policy returns `404`, preventing record-existence disclosure.

## 6. Create an incident

```http
POST /api/v1/incidents
Authorization: Bearer sop_REDACTED
Content-Type: application/json
Idempotency-Key: monitoring-inc-20260726-00041

{
  "title": "Production API unavailable",
  "description": "All regional health checks are failing.",
  "category": "Application",
  "priority": "P1",
  "assignment_group_id": 1
}
```

Required scope: `incidents:create`

Required fields: `title`, `description`, `assignment_group_id`.

`assignment_group_id` must identify an active IT fulfilment team in the API
client's tenant. `priority` accepts `P1`, `P2`, `P3`, or `P4` and defaults to
`P3`. Unknown JSON fields are rejected.

Successful creation returns `201 Created` and the governed ticket document.
The incident receives SLA records, assignment ownership, task history, and an
append-only audit event in the same transaction.

## 7. Update a ticket

```http
PATCH /api/v1/tickets/INC0000041
Authorization: Bearer sop_REDACTED
Content-Type: application/json
Idempotency-Key: resolver-inc41-progress-1

{
  "state": "In Progress",
  "priority": "P1",
  "assigned_to_id": 18
}
```

Required scope: `tickets:update`

Allowed fields are `state`, `priority`, and `assigned_to_id`. Use `null` to
clear the assignee. A non-null assignee must be active and belong to the owning
team.

The acting user must have update, assignment, and transition permissions and
must be an active member or manager of the owning team, unless the user is an
administrator. Approval and lifecycle guards are applied server-side. The API
cannot move a change into implementation merely because the token has update
scope.

## 8. Trigger an API workflow

```http
POST /api/v1/tickets/INC0000041/workflow-events
Authorization: Bearer sop_REDACTED
Content-Type: application/json
Idempotency-Key: automation-inc41-workflow-1

{}
```

Required scope: `workflows:execute`

The acting user must be authorized to manage and transition the ticket. A
successful request returns `202 Accepted`:

```json
{
  "data": {
    "event_id": "9320a248-f7b7-47ae-a398-97282c668413",
    "state": "Pending",
    "ticket": "INC0000041"
  }
}
```

Execution is durable and asynchronous. Administrators can inspect workflow
jobs, retries, evidence, and dead-letter state in the workflow administration
area.

## 9. CMDB auto-registration

```http
PUT /api/v1/cmdb/configuration-items
Authorization: Bearer sop_REDACTED
Content-Type: application/json

{
  "name": "web01.example.com",
  "ci_class": "Server",
  "environment": "Production",
  "operational_status": "Operational",
  "ip_address": "10.0.0.5"
}
```

Required scope: `cmdb:write`

Unlike the ticket-creation endpoints, this call is idempotent by design and
does **not** require an `Idempotency-Key` — it is meant to be called on every
agent run (cron, Puppet, systemd timer). The Configuration Item is matched by
`name` within the acting API client's tenant: the first call creates it
(`201`), every later call updates the same row (`200`). Only `name`,
`ci_class`, `environment`, `operational_status`, and `ip_address` are
accepted; unknown fields are rejected with `400`.

A ready-to-use POSIX shell agent lives at `tools/cmdb_sync_agent.sh` (curl and
standard Linux tools only — no facter, no Puppet module dependency), with an
example Puppet class at `deploy/puppet/cmdb_sync.pp.example` showing how to
drop it onto managed nodes and run it hourly via `cron`.

## 10. Monitoring ingestion

Monitoring sources use separate one-time credentials, not API-client tokens.
Create a source under **Administration → Integrations**, select its assignment
team, then copy the source ID and token.

```http
POST /api/v1/monitoring/7faacfb5-3f78-4cb4-a661-f3eeb20c9864/events
Authorization: Bearer REDACTED_MONITORING_TOKEN
Content-Type: application/json

{
  "external_id": "alert-prod-api-9001",
  "severity": "critical",
  "resource": "api-prod-01",
  "summary": "Production API health check failed",
  "observed_at": "2026-07-26T12:00:00Z",
  "source_url": "https://monitoring.example.com/alerts/9001"
}
```

Required fields are `external_id`, `severity`, `resource`, and `summary`.
Severity accepts `critical`, `high`, `medium`, `low`, or `info`. Additional
monitoring fields are preserved in the event payload.

The pair of source and `external_id` is deduplicated. First ingestion returns
`201`; a replay returns `200` with `"deduplicated": true`. ServiceOps creates
an EVT record and an investigation task routed to the source's configured team.

## 11. Error contract

```json
{
  "error": {
    "status": 403,
    "title": "Forbidden",
    "detail": "The API client lacks scope tickets:update.",
    "request_id": "9acdd549-4938-4eb2-bf8c-175ba8de2adc"
  }
}
```

| Status | Meaning |
|---|---|
| `400` | Invalid JSON, fields, parameters, transition, or idempotency key |
| `401` | Missing, invalid, or revoked token |
| `403` | Scope, role, team, tenant, or action is not authorized |
| `404` | Record does not exist or is intentionally hidden |
| `409` | Idempotency conflict, integrity failure, or state conflict |
| `429` | Reserved for enforced rate limits in a future compatible revision |
| `500` | Unexpected server failure; retain the request ID for investigation |

Clients should retry only transient `5xx` failures, using exponential backoff
with jitter and the same idempotency key. Do not automatically retry `400`,
`401`, `403`, `404`, or `409`.

## 12. cURL quick start

```bash
export SERVICEOPS_URL="https://serviceops.example.com"
read -rsp "ServiceOps API token: " SERVICEOPS_TOKEN
export SERVICEOPS_TOKEN

curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer ${SERVICEOPS_TOKEN}" \
  -H "Accept: application/json" \
  "${SERVICEOPS_URL}/api/v1/tickets?limit=25"
```

Avoid putting the token directly on the command line. Clear it when finished:

```bash
unset SERVICEOPS_TOKEN
```

## 13. Python example

```python
import os
import uuid
import requests

base_url = os.environ["SERVICEOPS_URL"].rstrip("/")
token = os.environ["SERVICEOPS_TOKEN"]
response = requests.post(
    f"{base_url}/api/v1/incidents",
    headers={
        "Authorization": f"Bearer {token}",
        "Idempotency-Key": str(uuid.uuid4()),
        "X-Request-ID": str(uuid.uuid4()),
    },
    json={
        "title": "Database connection failures",
        "description": "Connection failures exceed the alert threshold.",
        "category": "Database",
        "priority": "P2",
        "assignment_group_id": 2,
    },
    timeout=15,
)
response.raise_for_status()
print(response.json()["data"]["number"])
```

Always set connect/read timeouts, validate TLS, keep tokens in a secret
manager, and log request IDs rather than credentials or full sensitive bodies.

## 14. Current compatibility boundary

REST v1 is the supported integration surface. GraphQL is intentionally
deferred. CMDB registration (`PUT /api/v1/cmdb/configuration-items`, `cmdb:write`
scope) is the first CMDB surface exposed as a public REST resource; it is
deliberately narrow (upsert-by-name only, five fields). The current API does
not yet expose catalog ordering, REQ/RITM/SCTASK, PRB/PTASK, CHG/CTASK
creation, CI relationship management, attachment upload, users, or reporting as
public integration resources. Authenticated mobile sessions additionally use
an app-specific surface under `/api/v1/mobile` for bootstrap/profile,
push-device registration, notification inbox, approvals, knowledge search and
read-only CMDB; ticket comments and attachment list/download remain under the
ticket resource. These mobile
routes reject non-mobile API clients and are not shared API-key automation
contracts. Do not automate browser forms
as a substitute. Those resources will require explicit versioned contracts,
scopes, projections, idempotency, and compatibility tests.
