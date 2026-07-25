# ServiceOps

A self-contained, Docker-deployable enterprise service management platform. ServiceOps is an independent project and has no dependency on the Ollama project.

## Recommended web installation

```bash
chmod +x web-install.sh
./web-install.sh
```

Open `http://127.0.0.1:8090`. The Installation Center checks the Docker host,
application port, PostgreSQL, AD/LDAP, Keycloak OIDC metadata, and production
security policy before enabling deployment. It supports bundled or external
PostgreSQL, a local break-glass administrator, enterprise identity, and
separate Demo and Production profiles.

## Kubernetes and Helm

ServiceOps includes a hardened Helm chart for Kubernetes 1.27+:

```bash
cp deploy/kubernetes/values-production.example.yaml \
   deploy/kubernetes/values-production.yaml
./kubernetes-install.sh --preflight
./kubernetes-install.sh
```

Production requires an immutable image, multiple application replicas,
external HA PostgreSQL, and shared RWX upload storage. See the
[complete platform manual](docs/OPERATIONS_MANUAL.md) before deployment.

## Included workflows

- Incident management with priority, state, assignment, comments, search, and filtering
- Service request tracking
- Change management for agents and administrators
- Searchable knowledge base and article publishing
- Asset/CMDB inventory
- User administration and role-based access (`requester`, `agent`, `admin`)
- Audit history for logins and record changes
- Operational dashboard and database-aware health endpoint
- Persistent PostgreSQL storage and responsive web interface
- Problem, major-incident, release, and on-platform approval workflows
- Employee service catalog with governed fulfillment
- Customer service and HR case workspaces
- IT operations events, CMDB configuration items, and service dependency mapping
- Security incident, vulnerability, risk, compliance, and audit-finding workspaces
- Project, demand, program, objective, and agile portfolio work
- Field-service work orders, repairs, installations, and maintenance tracking
- In-app notifications and cross-module operational analytics

## Product positioning

ServiceOps implements broad, independently developed enterprise workflow capabilities. It does not include third-party proprietary code, licensed connectors, commercial data sets, or hosted AI services. External discovery, SIEM, HRIS, identity, email/SMS, mapping, and LLM capabilities require connections to the systems your organization actually uses.

See [docs/CAPABILITY_MATRIX.md](docs/CAPABILITY_MATRIX.md) for the detailed implemented and connection-dependent feature map.
See [docs/ITIL_IMPLEMENTATION.md](docs/ITIL_IMPLEMENTATION.md) for approval-chain, request hierarchy, change-governance, and SLA behavior.
See [docs/UI_CAPABILITY_MAPPING.md](docs/UI_CAPABILITY_MAPPING.md) for the platform user-interface feature mapping.

## Install on a server

The recommended installer supports either bundled PostgreSQL or an external PostgreSQL server:

```bash
chmod +x install.sh serviceopsctl
./install.sh
```

For complete server architecture, HTTPS, backup, external-database, recovery, upgrade, and security instructions, see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Manual Docker installation

1. Create your environment file:

   ```bash
   cp .env.example .env
   ```

2. Replace every password and secret in `.env`.

3. For bundled PostgreSQL, build and start:

   ```bash
   docker compose --env-file .env -f compose.yaml up --build -d
   ```

4. Open <http://localhost:8080>.

5. Verify:

   ```bash
   docker compose ps
   curl -fsS http://localhost:8080/health
   ```

The bundled database is stored in the `serviceops_postgres_data` Docker volume. Attachments are stored in `serviceops_uploads`; both survive container restarts.

For external PostgreSQL:

```bash
docker compose --env-file .env -f compose.external-db.yaml up --build -d
```

## First sign-in

The administrator username is `admin`; its password is the `ADMIN_PASSWORD` value in `.env`.

Two demo users are created on a fresh database:

- `agent` / `Agent123!`
- `employee` / `Employee123!`

Six IT manager accounts are also bootstrapped for CoreApps, Database, Network, Windows, Unix, and SSD. Their usernames follow `<team>.manager`, for example `database.manager`. Set `TEAM_MANAGER_PASSWORD` in `.env` before the first startup. Each manager controls their team and is automatically synchronized into the Change Control Board.

Change or remove demo credentials before exposing the application to a network.

## Operations

Use `./serviceopsctl status`, `health`, `doctor`, `logs`, `backup`, `restore`, `restart`, and `update`.

## Local tests

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

## Production notes

- Put the app behind an HTTPS reverse proxy or load balancer.
- Use long random values for `POSTGRES_PASSWORD`, `SECRET_KEY`, and `ADMIN_PASSWORD`.
- Back up the PostgreSQL volume.
- Add your organization’s SSO provider before broad internal rollout.
- ServiceOps does not use or bundle third-party proprietary platform code, branding, or APIs.
# ServiceOps
