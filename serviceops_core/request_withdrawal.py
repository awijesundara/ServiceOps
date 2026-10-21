"""Requester withdrawal of catalog requests (B-461).

The person a request was raised by or for (or an administrator) can
withdraw a requested item, or the whole request, while it is still open.
Withdrawing cancels the running approval chain (outstanding votes become
"No Longer Required"), skips open fulfilment tasks, stops the item's SLAs,
records history and audit, and tells the people who were waiting to act."""
from flask import abort

import app as core
from serviceops_core.localization import tr
from serviceops_models import now

ITEM_TERMINAL_STATES = ("Closed Complete", "Closed Incomplete", "Closed Skipped", "Rejected", "Cancelled")
TASK_TERMINAL_STATES = ("Closed Complete", "Closed Incomplete", "Closed Skipped")
REASON_LIMIT = 1000


def _is_party(user, catalog_request):
    return user.id in (catalog_request.requested_by_id, catalog_request.requested_for_id)


def can_withdraw_item(user, ritm):
    if not user.is_authenticated or not user.active or ritm.tenant_id != user.tenant_id:
        return False
    if ritm.state in ITEM_TERMINAL_STATES:
        return False
    return _is_party(user, ritm.request) or core.role_at_least(user.effective_role, "admin")


def can_withdraw_request(user, catalog_request):
    return any(can_withdraw_item(user, ritm) for ritm in catalog_request.items)


def _reason(reason):
    reason = (reason or "").strip()
    if not reason:
        abort(400, description=tr("Say why the request is being withdrawn."))
    if len(reason) > REASON_LIMIT:
        abort(400, description=tr("The reason has at most {limit} characters.", limit=REASON_LIMIT))
    return reason


def _withdraw(actor, ritm, reason):
    """Cancel one item; returns the user ids to notify."""
    notify = set()
    chain = core.approval_chain_for("ritm", ritm.id)
    if chain is not None and chain.state == "Running":
        notify |= {vote.approver_id for gate in chain.gates for vote in gate.votes if vote.state == "Requested"}
        core.cancel_approval_chain(chain)
        core.log_history("approval_chain", chain.id, "Approval chain cancelled", "state", "Running", "Cancelled",
                         details=tr("The request was withdrawn."), actor_id=actor.id)
    for task in ritm.tasks:
        if task.state in TASK_TERMINAL_STATES:
            continue
        before = task.state
        task.state = "Closed Skipped"
        note = tr("Withdrawn by {name}: {reason}", name=actor.name, reason=reason)
        task.work_notes = f"{task.work_notes}\n{note}".strip() if task.work_notes else note
        core.log_history("catalog_task", task.id, "Request withdrawn", "state", before, task.state,
                         actor_id=actor.id)
        if task.assignee_id:
            notify.add(task.assignee_id)
        elif task.assignment_group and task.assignment_group.manager_id:
            notify.add(task.assignment_group.manager_id)
    before = ritm.state
    ritm.state, ritm.stage = "Cancelled", "Cancelled"
    core.sync_slas("ritm", ritm.id, "Cancelled")
    core.log_history("ritm", ritm.id, "Request withdrawn", "state", before, "Cancelled", details=reason,
                     actor_id=actor.id)
    core.audit("request item withdrawn", ritm.number, reason[:200], user_id=actor.id, tenant_id=ritm.tenant_id)
    return notify


def settle_request(catalog_request):
    """Close the REQ once none of its items is still open."""
    states = [item.state for item in catalog_request.items]
    if not states or any(state not in ITEM_TERMINAL_STATES for state in states):
        return
    if all(state == "Cancelled" for state in states):
        final = "Cancelled"
    elif all(state in ("Closed Complete", "Cancelled") for state in states):
        final = "Closed Complete"
    else:
        final = "Closed Incomplete"
    if catalog_request.state != final:
        core.log_history("request", catalog_request.id, "State changed", "state", catalog_request.state, final)
        catalog_request.state = final
        catalog_request.closed_at = catalog_request.closed_at or now()


def _notify(actor, catalog_request, numbers, user_ids, reason):
    parties = {catalog_request.requested_by_id, catalog_request.requested_for_id}
    for user_id in (user_ids | parties) - {actor.id}:
        core.create_notification(
            user_id, tr("{numbers} withdrawn", numbers=", ".join(numbers)),
            tr("{name} withdrew {numbers}: {reason}", name=actor.name, numbers=", ".join(numbers), reason=reason),
            tenant_id=catalog_request.tenant_id, target_type="request", target_id=catalog_request.id,
            event_type="request.withdrawn",
            template_vars={"numbers": ", ".join(numbers), "name": actor.name, "reason": reason},
        )


def withdraw_item(actor, ritm, reason):
    if not can_withdraw_item(actor, ritm):
        abort(403, description=tr("Only the requester, the person it is for, or an administrator can withdraw an "
                                  "open request."))
    reason = _reason(reason)
    notify = _withdraw(actor, ritm, reason)
    settle_request(ritm.request)
    _notify(actor, ritm.request, [ritm.number], notify, reason)


def withdraw_request(actor, catalog_request, reason):
    if catalog_request.tenant_id != actor.tenant_id or not can_withdraw_request(actor, catalog_request):
        abort(403, description=tr("Only the requester, the person it is for, or an administrator can withdraw an "
                                  "open request."))
    reason = _reason(reason)
    notify, numbers = set(), []
    for ritm in catalog_request.items:
        if ritm.state not in ITEM_TERMINAL_STATES:
            notify |= _withdraw(actor, ritm, reason)
            numbers.append(ritm.number)
    settle_request(catalog_request)
    core.audit("request withdrawn", catalog_request.number, reason[:200], user_id=actor.id,
               tenant_id=catalog_request.tenant_id)
    _notify(actor, catalog_request, [catalog_request.number], notify, reason)
    return numbers

