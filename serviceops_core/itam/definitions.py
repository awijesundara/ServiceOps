"""The IT asset management record types."""
from datetime import date, timedelta

from flask import url_for

from serviceops_core.itam.registry import Field, ResourceType, register, readable_cis
from serviceops_core.localization import tr

CURRENCIES = ("JPY", "USD", "EUR", "GBP", "AUD", "SGD", "CNY", "INR", "LKR")


# ---------------------------------------------------------------- suppliers
def _supplier_delete_blocker(supplier):
    if supplier.contracts:
        return tr("{count} contracts still reference this supplier. Deactivate it instead.",
                  count=len(supplier.contracts))
    return None


def _supplier_contracts(supplier):
    return [
        (contract.name, url_for("itam_edit", kind="contracts", record_id=contract.id),
         contract_status(contract)[0])
        for contract in sorted(supplier.contracts, key=lambda c: c.name.casefold())
    ]


SUPPLIERS = register(ResourceType(
    key="suppliers", model_name="Supplier", label="Supplier", plural="Suppliers", icon="S",
    description="Vendors, resellers, service providers and manufacturers.",
    fields=(
        Field("name", "Name", required=True, in_list=True),
        Field("supplier_type", "Type", "choice", choices=(
            "Vendor", "Reseller", "Manufacturer", "Service provider", "Maintenance", "Other"), in_list=True),
        Field("website", "Website", "url", max_length=255),
        Field("email", "Email", "email", max_length=255, in_list=True),
        Field("phone", "Phone", max_length=60, in_list=True),
        Field("account_number", "Our account number", max_length=80),
        Field("address", "Address", "textarea"),
        Field("notes", "Notes", "textarea"),
        Field("active", "Active", "bool", in_list=True),
    ),
    delete_blocker=_supplier_delete_blocker,
    search_fields=("name", "email", "phone"),
    related=(("Contracts", _supplier_contracts),),
))


# ---------------------------------------------------------------- contracts
def notice_date(contract):
    """The last day to give notice, or None without an end date."""
    if not contract.end_date:
        return None
    days = contract.notice_days or 0
    if (contract.end_date - date.min).days < days:
        return date.min
    return contract.end_date - timedelta(days=days)


def contract_status(contract, today=None):
    """(label, tone) for a contract on `today`."""
    today = today or date.today()
    if not contract.active:
        return tr("Inactive"), "muted"
    if contract.start_date and today < contract.start_date:
        return tr("Not started"), "muted"
    if contract.end_date and today > contract.end_date:
        return tr("Expired"), "bad"
    deadline = notice_date(contract)
    if deadline and today >= deadline:
        return tr("Notice period"), "warn"
    if contract.end_date and (contract.end_date - today).days <= (contract.notice_days or 0) + 30:
        return tr("Expiring soon"), "warn"
    return tr("Active"), "ok"


def _validate_contract(contract, values):
    start, end = values.get("start_date"), values.get("end_date")
    if start and end and end < start:
        return tr("The end date must be on or after the start date.")
    return None


def _contract_cis(contract):
    return [(ci.name, url_for("ci_edit", ci_id=ci.id), ci.ci_class) for ci in readable_cis(contract.cis)]


CONTRACTS = register(ResourceType(
    key="contracts", model_name="Contract", label="Contract", plural="Contracts", icon="C",
    description="Support, maintenance, lease and subscription contracts, with renewal and notice dates.",
    fields=(
        Field("name", "Name", required=True, in_list=True),
        Field("number", "Contract number", max_length=80, in_list=True),
        Field("contract_type", "Type", "choice", choices=(
            "Support", "Maintenance", "Lease", "Subscription", "Service", "Warranty", "License", "Other"),
            in_list=True),
        Field("supplier_id", "Supplier", "ref", ref="suppliers", in_list=True),
        Field("start_date", "Start date", "date"),
        Field("end_date", "End date", "date", in_list=True),
        Field("notice_days", "Notice period (days)", "int", maximum=3650,
              help="Days before the end date by which notice must be given. The owner is alerted then."),
        Field("renewal", "Renewal", "choice", choices=(
            ("none", "Ends"), ("tacit", "Renews automatically"), ("express", "Renews on agreement"))),
        Field("cost", "Cost", "money", in_list=True),
        Field("currency", "Currency", "choice", choices=CURRENCIES),
        Field("billing_period", "Billing period", "choice", choices=(
            ("monthly", "Monthly"), ("quarterly", "Quarterly"), ("yearly", "Yearly"), ("once", "One-off"))),
        Field("owner_id", "Owner", "user", in_list=True, help="Receives the renewal alert."),
        Field("cis", "Covered configuration items", "cis"),
        Field("notes", "Notes", "textarea"),
        Field("active", "Active", "bool"),
    ),
    status=contract_status,
    validate=_validate_contract,
    order_by="end_date",
    search_fields=("name", "number"),
    related=(("Covered configuration items", _contract_cis),),
))
