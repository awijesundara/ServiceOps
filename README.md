<div align="center">

<img src="static/brand/serviceops-mark.png" width="100" alt="ServiceOps logo">

# ServiceOps

### Your service desk. Your infrastructure. One connected workspace.

Self-hosted IT service management for incidents, requests, changes, assets and approvals.

[![Version](https://img.shields.io/badge/version-1.113.30-003E4C?style=for-the-badge)](https://github.com/awijesundara/ServiceOps/releases)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](pyproject.toml)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)](https://github.com/awijesundara/ServiceOps/wiki/Deployment-and-Recovery)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white)](charts/serviceops)
[![iOS app](https://img.shields.io/badge/Native_iOS-000000?style=for-the-badge&logo=apple&logoColor=white)](https://github.com/awijesundara/ServiceOps_iOS)

**[Explore the app](https://github.com/awijesundara/ServiceOps/wiki/App-Guide)** · **[Get started](https://github.com/awijesundara/ServiceOps/wiki/Deployment-and-Recovery)** · **[REST API](https://github.com/awijesundara/ServiceOps/wiki/REST-API-Reference)** · **[Releases](https://github.com/awijesundara/ServiceOps/releases)**

</div>

## Project pulse

Live GitHub indicators link to their underlying records. Counts update independently of application releases.

| Delivery & quality | Repository activity | Community & reach |
| :--- | :--- | :--- |
| [![Supply-chain gate](https://img.shields.io/github/actions/workflow/status/awijesundara/ServiceOps/supply-chain.yml?branch=main&label=supply-chain%20gate)](https://github.com/awijesundara/ServiceOps/actions/workflows/supply-chain.yml) | [![Last commit](https://img.shields.io/github/last-commit/awijesundara/ServiceOps/main?label=last%20commit)](https://github.com/awijesundara/ServiceOps/commits/main) | [![Stars](https://img.shields.io/github/stars/awijesundara/ServiceOps?style=flat&label=stars)](https://github.com/awijesundara/ServiceOps/stargazers) |
| [![CodeQL](https://img.shields.io/github/actions/workflow/status/awijesundara/ServiceOps/codeql.yml?branch=main&label=CodeQL)](https://github.com/awijesundara/ServiceOps/actions/workflows/codeql.yml) | [![Commit activity](https://img.shields.io/github/commit-activity/m/awijesundara/ServiceOps?label=commits%2Fmonth)](https://github.com/awijesundara/ServiceOps/graphs/commit-activity) | [![Forks](https://img.shields.io/github/forks/awijesundara/ServiceOps?style=flat&label=forks)](https://github.com/awijesundara/ServiceOps/forks) |
| [![RPM builds](https://img.shields.io/github/actions/workflow/status/awijesundara/ServiceOps/rpm.yml?branch=main&label=RPM%20builds)](https://github.com/awijesundara/ServiceOps/actions/workflows/rpm.yml) | [![Open issues](https://img.shields.io/github/issues/awijesundara/ServiceOps?label=open%20issues)](https://github.com/awijesundara/ServiceOps/issues) | [![Contributors](https://img.shields.io/github/contributors/awijesundara/ServiceOps?label=contributors)](https://github.com/awijesundara/ServiceOps/graphs/contributors) |
| [![Latest release](https://img.shields.io/github/v/release/awijesundara/ServiceOps?label=latest%20release)](https://github.com/awijesundara/ServiceOps/releases/latest) | [![Open PRs](https://img.shields.io/github/issues-pr/awijesundara/ServiceOps?label=open%20PRs)](https://github.com/awijesundara/ServiceOps/pulls) | [![Release downloads](https://img.shields.io/github/downloads/awijesundara/ServiceOps/total?label=release%20downloads)](https://github.com/awijesundara/ServiceOps/releases) |
| [![Top language](https://img.shields.io/github/languages/top/awijesundara/ServiceOps?label=top%20language)](https://github.com/awijesundara/ServiceOps) | [![Code size](https://img.shields.io/github/languages/code-size/awijesundara/ServiceOps?label=code%20size)](https://github.com/awijesundara/ServiceOps) | [![Watchers](https://img.shields.io/github/watchers/awijesundara/ServiceOps?style=flat&label=watchers)](https://github.com/awijesundara/ServiceOps/watchers) |

## A workspace for the whole service lifecycle

<table>
<tr>
<td width="50%"><img src="https://raw.githubusercontent.com/wiki/awijesundara/ServiceOps/docs/readme/dashboard.png" alt="ServiceOps dashboard with service metrics and assigned work"><br><strong>See the work that matters</strong><br>Service health, assigned work and operational reporting.</td>
<td width="50%"><img src="https://raw.githubusercontent.com/wiki/awijesundara/ServiceOps/docs/readme/incident_detail.png" alt="Incident record with assignment, status and activity"><br><strong>Move incidents toward resolution</strong><br>Ownership, investigation, notes and auditable activity.</td>
</tr>
<tr>
<td width="50%"><img src="https://raw.githubusercontent.com/wiki/awijesundara/ServiceOps/docs/screenshots/cmdb.png" alt="ServiceOps configuration management database"><br><strong>Connect services and infrastructure</strong><br>Configuration items, ownership and service relationships.</td>
<td width="50%"><img src="https://raw.githubusercontent.com/wiki/awijesundara/ServiceOps/docs/evidence/20261010-serviceops-review/web-theme-navy.png" alt="Executive Navy theme and professional theme selection"><br><strong>Make the workspace your own</strong><br>Account-level themes, accessibility and display preferences.</td>
</tr>
</table>

[See all workflows in the visual app guide →](https://github.com/awijesundara/ServiceOps/wiki/App-Guide)

## What you can manage

| Workspace | Capabilities |
| :--- | :--- |
| **Service desk** | Incidents, major incidents, problems, assignment, comments and attachments. |
| **Employee self-service** | Service catalog, requests, approval routing and fulfillment tasks. |
| **Change governance** | Affected CIs, risk, planned windows, implementation/test/backout plans and manager, owner or CCB review. |
| **Infrastructure** | CMDB, assets, service relationships, ownership, suppliers, contracts and NetBox integration. |
| **Service performance** | SLA tracking, analytics, service status, task boards and operational history. |
| **Client support & knowledge** | Client organizations, contacts, supported mailboxes and reusable knowledge articles. |
| **Identity & administration** | Users, teams, permissions, integrations and administrator-controlled AI settings. |
| **AI assistance** | Role-scoped investigation and structured drafts, with human review before submission. |
| **Mobile & integrations** | Browser/PWA access, a native iOS client, REST API and read-only MCP interfaces. |

## Run on your infrastructure

**Python application · PostgreSQL · Web and background workers · Docker / Kubernetes · RPM packages**

Use the [deployment and recovery guide](https://github.com/awijesundara/ServiceOps/wiki/Deployment-and-Recovery) for prerequisites, configuration, installation, health checks, backups and upgrades. Release artifacts are available on the [Releases page](https://github.com/awijesundara/ServiceOps/releases); Kubernetes packaging lives in the [Helm chart](charts/serviceops).

[Architecture overview](https://github.com/awijesundara/ServiceOps/wiki/Home#deployment-at-a-glance) · [Offline deployment](https://github.com/awijesundara/ServiceOps/wiki/Offline-Deployment) · [Monitoring](https://github.com/awijesundara/ServiceOps/wiki/Monitoring) · [Security policy](https://github.com/awijesundara/ServiceOps/wiki/Security-Policy)

## Native iOS companion

Take your workspace with you: Home, tickets, approvals, knowledge, CMDB and front/rear rack views. The app uses your ServiceOps account and exposes information according to server permissions.

**[Explore ServiceOps for iOS →](https://github.com/awijesundara/ServiceOps_iOS)** · [View the latest mobile previews](https://github.com/awijesundara/ServiceOps_iOS#screenshots) · [Native ticket details](https://github.com/awijesundara/ServiceOps/wiki/Native-Ticket-Details)

## Explore the documentation

| Start here | Build & integrate | Operate & contribute |
| :--- | :--- | :--- |
| [Visual app guide](https://github.com/awijesundara/ServiceOps/wiki/App-Guide) | [REST API reference](https://github.com/awijesundara/ServiceOps/wiki/REST-API-Reference) | [Deployment & recovery](https://github.com/awijesundara/ServiceOps/wiki/Deployment-and-Recovery) |
| [Operations manual](https://github.com/awijesundara/ServiceOps/wiki/Operations-Manual) | [Engineering reference](https://github.com/awijesundara/ServiceOps/wiki/Engineering-Reference) | [Implementation plan](https://github.com/awijesundara/ServiceOps/wiki/Implementation-Plan) |
| [Download the PDF manual](https://raw.githubusercontent.com/wiki/awijesundara/ServiceOps/docs/ServiceOps_Complete_Platform_Manual.pdf) | [Database migrations](https://github.com/awijesundara/ServiceOps/wiki/Database-Migrations) | [Current backlog](https://github.com/awijesundara/ServiceOps/wiki/Backlog) |

Found a problem or have a feature proposal? [Open an issue](https://github.com/awijesundara/ServiceOps/issues/new) with the relevant workflow, expected behavior and reproduction details. See the [engineering reference](https://github.com/awijesundara/ServiceOps/wiki/Engineering-Reference) before contributing implementation changes.

This repository contains application code, tests and deployment tooling. The wiki owns product guides, screenshots, diagrams and the platform manual.
