# ServiceOps collaboration instructions

ServiceOps is an independent, production-oriented ITSM platform. It is completely separate from the Ollama project. Never modify or use files from /Users/anushka/Github/Ollama while working on ServiceOps.

## Project direction

1. ServiceOps is inspired by established ITIL and enterprise ITSM patterns, but must not falsely claim complete ServiceNow compatibility or parity.
2. Preserve the existing product and improve it through bounded modules and stable interfaces. Do not perform a disguised rewrite.
3. PostgreSQL is the only supported standard production database.
4. REST is the primary API. Do not introduce GraphQL without a demonstrated consumer requirement.
5. The UI is light-mode only. Dark mode is an explicit governed non-requirement.
6. The product is responsive and PWA-first. Preserve authentication and API designs that could support native clients later.
7. Configuration should be Git-backed and declarative where practical. Database records represent deployed runtime configuration.
8. Prioritize security and platform foundations before decorative or low-value feature expansion.
9. Preserve existing data through reversible, versioned migrations. Never modify production schemas ad hoc.
10. Enterprise integrations must be optional adapters, not separate architectural forks.

## Production-only policy

Never restore or introduce:

- Demo mode
- Demo-agent personas
- Shared demo accounts
- Temporary test credentials in the UI
- Weak default passwords
- Sample operational records in production
- Automatically seeded production tickets
- Visible credentials
- Hard-coded secrets
- JNX branding or company-specific text

Legacy identities referenced by historical approvals or audit records must be disabled or tombstoned, not hard-deleted if deletion would damage history.

The installer and administrator settings must support customizable:

- Company name
- Product display name
- PNG company logo
- Branding colors
- Authentication providers
- Database connection
- SMTP
- Webhooks
- Monitoring ingestion
- Microsoft Teams
- LDAP/Active Directory
- Keycloak/OIDC

## Authentication and authorization

Supported authentication patterns are:

- Local bootstrap administrator
- Active Directory/LDAP
- Keycloak/OIDC

The local bootstrap administrator must be handled securely and must not have a known default password.

Enforce tenant_id and tenant-aware authorization everywhere, even when only one organization currently exists.

Tenant resolution must fail closed. Never silently default an authenticated user with a missing tenant_id to tenant 1.

Tenant boundaries must be enforced in:

- Queries
- Writes
- Relationships
- Background jobs
- Notifications
- Webhooks
- API endpoints
- Audit records
- Unique constraints
- Administration screens
- Import/export operations

AD group mappings must support automatic user provisioning and team assignment. For example:

gg_unix -> Unix

Administrators must be able to configure:

- AD group to ServiceOps team mappings
- Team membership
- Team manager
- CCB eligibility
- Approval authority
- Multiple applicable AD groups
- Conflict resolution and mapping priority
- Disabled and removed-user handling

## IT teams and governance

The established teams are:

- CoreApps
- Database
- Network
- Windows
- Unix
- SSD

Each team has a manager with management-level authority for that team. Team managers can be configured as CCB members.

CCB means Change Control Board.

Incidents and changes may be visible across IT teams, but mutation permissions must be more restrictive. Visibility never grants the authority to modify, assign, progress, resolve, approve, or close a record.

Requests, RITMs, catalog tasks, problem tasks, and change tasks must be visible and mutable according to requester, fulfiller team, assignment, managerial authority, approval role, and administrative privileges.

A team must not progress or resolve another team's assigned work merely because the record is visible.

## ITIL record model

Preserve the proper relationship model:

- INC: Incident
- PRB: Problem
- PTASK: Problem Task
- CHG: Change Request
- CTASK: Change Task
- REQ: Request container
- RITM: Requested Item
- SCTASK: Catalog fulfilment task
- KB: Knowledge article
- CI: Configuration Item

Key rules:

- INC restores service.
- PRB investigates root cause.
- PTASK is investigation work under a PRB.
- CHG controls and authorizes production modification.
- CTASK executes a work package under a CHG.
- REQ contains one or more RITMs.
- RITM represents an individual requested catalog item.
- SCTASK fulfils a RITM.
- Approvals are decision records, not CTASKs or SCTASKs.
- SLA records track commitments against tasks.
- Knowledge preserves reusable resolutions and workarounds.
- CMDB relationships identify affected and impacted infrastructure and services.

Do not collapse these records into one generic ticket workflow.

## Change governance

Support Standard, Normal, and Emergency changes with distinct governance.

A change must not reach implementation states unless its required approval chain is satisfied.

Normal-change governance should support:

- Technical/team-manager approval
- Change-manager authorization
- CCB approval
- Risk and impact assessment
- Planned implementation window
- Conflict detection
- Implementation plan
- Test plan
- Backout plan
- Affected CIs
- Impacted services
- Change tasks
- Post-implementation review

Emergency changes require an accelerated but auditable approval route. "Submitted late" is not an emergency justification.

Standard changes remain recorded but may use a governed pre-authorized template.

Material modifications after approval must:

1. Be recorded in ticket history.
2. Identify the actor and changed fields.
3. Preserve before and after values safely.
4. Invalidate affected approvals.
5. Return the record to the appropriate pre-approval state.
6. Create a new approval cycle.
7. Notify the correct active approvers exactly once.
8. Never reactivate obsolete approval records.

Examples of material change fields include scope, implementation plan, test plan, backout plan, affected CIs, risk, impact, schedule, assignment group, and business purpose.

## Catalog routing

Catalog item routing must be configurable by administrators and must not be hard-coded into application logic.

Current expected defaults include:

- Software Request -> Windows
- Laptop Request -> Windows

Administrators must be able to create new catalog items and configure:

- Owning fulfilment team
- Approval policy
- Form variables
- Fulfilment tasks
- Sequential or parallel fulfilment
- SLA policy
- Eligibility
- Automation
- Required change creation
- Active/inactive state

## Security requirements

Treat all authorization as server-side enforcement. Hiding a button is not authorization.

Required controls include:

- CSRF protection
- Secure session lifecycle
- SESSION_COOKIE_SECURE enabled in production
- HttpOnly and appropriate SameSite cookies
- Content Security Policy
- Safe return/start-page validation to prevent open redirects
- Tenant-scoped authorization
- Immutable or tamper-evident audit history
- Request size limits
- File-upload validation
- Malware scanning or quarantine adapter
- Content-type and extension verification
- Cryptographic attachment hashes
- Attachment authorization and retention controls
- SSRF-resistant webhooks
- DNS and redirect validation for outbound webhook destinations
- Signed webhooks
- Secret redaction
- Rate limiting
- Idempotency for mutating integrations
- Dependency and container scanning
- Least-privilege containers and database roles

Never log passwords, tokens, connection strings, LDAP bind passwords, session identifiers, or other secrets.

## Migrations and releases

Alembic migration history, source code, Docker image, Compose configuration, Helm chart, installer, documentation, and release evidence must agree on the same version and migration head.

Never:

- Rewrite an already-deployed migration
- Delete a migration to make a test pass
- Stamp a database without verifying its schema
- Reset or flush a database without explicit user authorization
- Use destructive Git commands
- Discard unrelated user changes

Every new migration must be:

- Versioned
- Reversible where technically possible
- Tested against PostgreSQL
- Verified from the previous supported revision
- Verified at head
- Tested for rollback
- Included in the built deployment image

## Deployment targets

Maintain support for:

- Docker Compose with bundled PostgreSQL
- Docker Compose with external PostgreSQL
- Kubernetes through Helm
- External LDAP/AD
- Keycloak/OIDC
- SMTP
- Signed webhooks
- Monitoring ingestion
- Microsoft Teams

The web installer and post-installation administration interface must validate connections without exposing secrets.

Installer success checks should cover:

- Database connectivity and privileges
- Migration status
- Persistent storage
- LDAP bind and search
- OIDC discovery and callback configuration
- SMTP connection
- Webhook destination
- Teams integration
- Background worker
- Application health
- Required secrets
- TLS/proxy assumptions

Do not claim that a connection works unless it has actually been tested.

## Engineering workflow

Before changing anything:

1. Read the repository status and current branch.
2. Inspect all relevant implementation, migration, test, deployment, and documentation files.
3. Preserve existing uncommitted changes.
4. Identify the root cause rather than patching only the visible UI.
5. State the intended bounded change.
6. Check whether an existing migration or interface already covers it.

When implementing:

1. Keep business rules in testable services or policy modules.
2. Avoid expanding the monolithic application file unnecessarily.
3. Enforce policy at the service/database boundary, not only in templates.
4. Add negative authorization tests, not only successful-path tests.
5. Add tenant-isolation tests.
6. Add migration tests for schema changes.
7. Keep API, UI, worker, and notification behavior consistent.
8. Update controlled documentation and backlog entries alongside implementation.
9. Do not mark backlog items complete without corresponding evidence.

## Documentation control

Controlled local documentation begins at:

docs/DOCUMENTATION_INDEX.md

Keep these synchronized where they exist:

- Documentation index
- Product backlog
- Traceability matrix
- Architecture decisions
- Security model
- ITIL workflow documentation
- API documentation
- Installation and deployment manual
- Administrator manual
- User manual
- Production-readiness assessment
- Migration and rollback instructions
- Release evidence

The docs directory may be excluded from GitHub, but it still must be maintained locally. Do not delete it because it is gitignored.

## Validation expectations

For each meaningful change, run proportionate validation, including as applicable:

- Full automated test suite
- Focused regression tests
- PostgreSQL migration upgrade verification
- PostgreSQL rollback verification
- Linting
- Static typing
- Dependency audit
- Supply-chain verification
- Container image build
- Docker Compose startup
- Application and worker health checks
- Browser-level workflow testing
- Cross-team authorization testing
- Cross-tenant isolation testing
- Approval and reapproval testing
- Attachment security testing
- Webhook SSRF and signing tests
- LDAP/OIDC integration tests where configured
- Kubernetes template/lint checks
- Persistence and restart tests

A healthy /health endpoint alone is not sufficient production evidence.

## Deployment after changes

After every completed code change:

1. Build a fresh ServiceOps image from the exact current source.
2. Ensure the image contains the expected migration head.
3. Deploy the updated stack.
4. Run migrations safely.
5. Confirm application, worker, database, and persistent storage health.
6. Verify the changed workflow in the running application.
7. Give the user the URL and exact test scenario.
8. Report the deployed image/version and migration revision.
9. Report any validation that could not be performed.

Do not tell the user a change is deployed until the running environment has been checked.

## Current review priorities

Re-check these against the current source because another collaborator may already have changed them:

1. Ensure the deployed image contains the database's current Alembic revision.
2. Remove hard-coded migration-rehearsal revision assumptions.
3. Make tenant context fail closed.
4. Add tenant_id to dependent records and tenant-scope applicable constraints.
5. Investigate Gunicorn worker timeouts, worker deaths, and possible OOM conditions.
6. Align versions across the installer, Compose, Helm, environment examples, image tags, and release evidence.
7. Enable secure production cookie defaults.
8. Complete attachment scanning, quarantine, hashing, storage, and authorization.
9. Harden webhooks against DNS rebinding and redirect-based SSRF.
10. Prevent duplicate reapproval notifications.
11. Validate stored redirect/start-page destinations.
12. Add a Content Security Policy.
13. Continue decomposing oversized modules through stable bounded interfaces.
14. Expand REST API coverage only through governed, versioned endpoints.
15. Add browser, accessibility, load, failover, LDAP, Keycloak, SMTP, Teams, and Kubernetes evidence.

## Collaboration report format

At the end of each task, report:

- Outcome
- Files changed
- Schema/migration changes
- Security and authorization impact
- Tests executed and exact results
- Deployment image/version
- Deployed migration revision
- Runtime health checks
- Manual test URL and credentials only if securely created for an explicitly authorized test environment
- Documentation/backlog updates
- Remaining risks or unverified areas

Use precise language:

- "Implemented" means source code changed.
- "Tested" means name the exact test and result.
- "Deployed" means the running environment was rebuilt and verified.
- "Production ready" requires documented production-readiness evidence and cannot be inferred from a passing unit-test suite.

If you encounter an ambiguous product decision, collect all material questions and ask them together. Do not repeatedly interrupt the user for small implementation choices that can be safely inferred from the established architecture.
