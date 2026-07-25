# Capability matrix

ServiceOps is an independently developed enterprise workflow platform. This matrix separates working local capabilities from integrations that require an organization's external systems.

## Working in the Docker deployment

| Product area | Implemented capability |
|---|---|
| IT service management | Incidents, REQ/RITM/SCTASK requests, normal/standard/emergency changes, problems, major incidents, releases, comments, assignment, priority, lifecycle states |
| Employee self-service | Service catalog, knowledge search, request tracking, sequential/parallel approval chains, fulfillment tasks |
| Customer service | Support cases, complaints, returns/RMA, onboarding cases |
| HR service delivery | Benefits, payroll, employee relations, HR systems, and onboarding cases |
| IT operations | Event and alert records, configuration items, operational status, dependency/service mapping |
| Security operations | Security incidents, vulnerabilities, DLP cases, and threat-intelligence work |
| Risk and compliance | Risks, control tests, policy exceptions, and audit findings |
| Strategic portfolio | Demands, projects, programs, objectives, and agile epics |
| Field service | Work orders, installations, repairs, and preventive maintenance |
| Platform governance | Role-based access, multi-stage all/any/majority approval chains, team managers, Change Control Board membership, audit log, notifications, due dates, risk and priority |
| Service level management | SLA definitions, task SLA instances, pause/resume conditions, breach targets, completion tracking |
| Change enablement | Owning IT team, manager assessment, change type, implementation/test/backout plans, risk score, impact, affected CI, weekly CCB authorization, schedule conflict checks |
| Analytics | Ticket state, priority, domain workload, and overdue-work measures |
| Deployment | PostgreSQL persistence, health checks, responsive web UI, Gunicorn, Docker Compose |

## Connection-dependent capabilities

These cannot truthfully be preconfigured without the systems, credentials, policies, and data belonging to the deploying organization:

- SAML/OIDC single sign-on, MFA, SCIM, and directory synchronization
- Email, SMS, voice, chat, and contact-center channels
- SIEM, EDR, vulnerability scanner, threat-intelligence, and DLP ingestion
- Cloud, network, endpoint, and application infrastructure discovery
- HRIS, payroll, ERP, CRM, procurement, DevOps, and source-control integrations
- GIS routing, technician geolocation, parts inventory, and contractor marketplaces
- AI/LLM summarization, autonomous agents, predictive routing, and voice agents
- Enterprise data residency, legal retention, eDiscovery, and organization-specific compliance controls
- Mobile push notifications and native mobile/offline applications

Those integrations should be added through explicit adapters with secrets stored outside the repository.
