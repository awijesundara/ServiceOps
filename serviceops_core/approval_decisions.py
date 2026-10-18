"""Serialize approval decisions and refresh state read by earlier requests."""
from serviceops_models import ApprovalChain, db


def refresh_locked_approval(vote):
    # Delegation may already be pending on the vote. Do not flush it before
    # locking the chain (all decisions must acquire locks in the same order),
    # and refresh only lifecycle fields so the acting approver is preserved.
    with db.session.no_autoflush:
        chain = ApprovalChain.query.filter_by(id=vote.gate.chain_id).with_for_update().populate_existing().one()
        db.session.expire(chain, ["gates"])
        for gate in chain.gates:
            db.session.refresh(gate, attribute_names=["state"])
            db.session.expire(gate, ["votes"])
            for member_vote in gate.votes:
                db.session.refresh(member_vote, attribute_names=["state"])
