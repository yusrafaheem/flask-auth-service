"""AuditLog: an append-only record of security-relevant events.

user_id is nullable and email_at_time is stored redundantly alongside it
on purpose: a registration attempt with an unknown email, or a login
attempt against an email that doesn't exist, is exactly the kind of event
this table needs to capture for abuse investigation -- and neither has a
real user_id to attach to. Storing the email as it was at the time (rather
than only via a join to users.email) also means the audit trail still
reads correctly after a user changes their email or is deleted.
"""

import uuid
from datetime import datetime, timezone

from app.extensions import db


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)

    event_type = db.Column(db.String(50), nullable=False, index=True)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=True, index=True)
    email_at_time = db.Column(db.String(255), nullable=True)

    ip_address = db.Column(db.String(45), nullable=True)  # IPv6-safe length
    detail = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow, index=True)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"<AuditLog {self.event_type} user={self.user_id}>"
