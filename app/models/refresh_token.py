"""RefreshToken: the DB-backed half of session revocation.

The JWT refresh token itself is stateless and self-verifying (see
app/security/tokens.py), but a stateless token can't be revoked by itself
-- once issued, it's valid until it expires, full stop. This table is
what makes logout and "revoke all sessions" actually work: each issued
refresh token gets a row keyed by its JWT ID (`jti`), and
app/routes/auth.py's refresh/logout endpoints check `revoked_at IS NULL`
before honoring a token, in addition to verifying its signature and
expiry.
"""

import uuid
from datetime import datetime, timezone

from app.extensions import db


def _uuid() -> str:
    return str(uuid.uuid4())


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RefreshToken(db.Model):
    __tablename__ = "refresh_tokens"

    id = db.Column(db.String(36), primary_key=True, default=_uuid)
    jti = db.Column(db.String(36), unique=True, nullable=False, index=True)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False, index=True)

    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_utcnow)

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None and self.expires_at > _utcnow()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return f"<RefreshToken {self.jti} user={self.user_id}>"
