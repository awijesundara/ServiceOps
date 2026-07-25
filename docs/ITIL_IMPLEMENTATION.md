# ITIL implementation

## Approval chain engine

Approval chains contain ordered gates. Each gate supports:

- `all`: every requested approver must approve
- `any`: the first approval completes the gate and remaining votes become no longer required
- sequential activation: gate N+1 is not requested until gate N is approved
- immediate rejection: one rejection stops the chain and rejects the target record
- user and group-derived approvers
- individual comments, decision timestamps, notification records, and audit events

Catalog requests use manager approval followed by fulfillment authorization. Normal and emergency changes use the owning IT team manager's assessment followed by weekly Change Control Board (CCB) authorization. Standard changes use the reduced policy path.

## Request management hierarchy

- `REQ`: request envelope and requested-for identity
- `RITM`: one requested catalog item, variables, approval stage, due date, and SLA
- `SCTASK`: fulfillment task, support group, assignee, work notes, and completion state

Approval completion creates the fulfillment task. Task closure rolls state up to the RITM and REQ.

## Change enablement

Change records capture the owning IT team, change type, impact, numeric risk, affected CI, planned schedule, implementation plan, test plan, and backout plan. The first approval belongs to that team's manager. The second approval uses majority voting by the Change Control Board, whose membership is synchronized from all IT team managers. Conflict detection checks overlapping work against the same CI.

## IT organization and CCB

The configured fulfillment teams are CoreApps, Database, Network, Windows, Unix, and SSD. Each team has a dedicated manager account, a `manager` group membership, and management authority for that support group. Every team manager is also a member of the Change Control Board. The CoreApps manager is initially assigned as CCB chair.

## Service level management

SLA definitions attach task-SLA instances based on record type and priority. Each instance records start, pause, target breach, completion, accumulated pause duration, and breach status. Pending and on-hold states pause clocks; resuming shifts the breach target.

## Service configuration

The ITIL configuration workspace exposes support/approval groups, group membership, business service ownership, criticality, operational state, and SLA definitions. CMDB configuration items and relationships provide service-impact context.
