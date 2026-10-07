"""Contract renewal alerts: once a contract reaches the last day to give
notice (end date minus its notice period), its owner, or every active
administrator of the tenant when it has none, is notified once for that end
date. Changing the end date re-arms the alert."""
from datetime import date

from flask import url_for


def send_contract_alerts(today=None):
    import app as core_app
    from serviceops_core.itam.definitions import notice_date
    from serviceops_models import Contract, Tenant, User, db

    today = today or date.today()
    sent = 0
    for tenant in Tenant.query.filter_by(active=True):
        contracts = Contract.query.filter(
            Contract.tenant_id == tenant.id, Contract.active.is_(True), Contract.end_date.isnot(None),
            Contract.end_date >= today,
        ).all()
        for contract in contracts:
            deadline = notice_date(contract)
            if not deadline or today < deadline or contract.alerted_for_end_date == contract.end_date:
                continue
            recipients = [contract.owner] if contract.owner and contract.owner.active else User.query.filter(
                User.tenant_id == tenant.id, User.active.is_(True), User.role.in_(["admin", "superadmin"]),
            ).all()
            renewal = {"tacit": "renews automatically", "express": "renews only on agreement"}.get(
                contract.renewal, "ends")
            supplier = f" with {contract.supplier.name}" if contract.supplier else ""
            body = (f"Contract {contract.name}{supplier} {renewal} on {contract.end_date:%Y-%m-%d}. "
                    f"The last day to give notice is {deadline:%Y-%m-%d}.")
            try:
                link = url_for("itam_edit", kind="contracts", record_id=contract.id)
            except RuntimeError:
                link = f"/itam/contracts/{contract.id}"
            for user in recipients:
                core_app.create_notification(
                    user.id, f"Contract notice period: {contract.name}", f"{body} {link}",
                    tenant_id=tenant.id, target_type="contract", target_id=contract.id,
                    event_type="contract.notice", template_vars={
                        "contract": contract.name, "end_date": f"{contract.end_date:%Y-%m-%d}",
                        "notice_date": f"{deadline:%Y-%m-%d}",
                    },
                )
            contract.alerted_for_end_date = contract.end_date
            sent += 1
        db.session.commit()
    return sent
