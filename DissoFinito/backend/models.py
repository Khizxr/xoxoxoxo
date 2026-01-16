from datetime import datetime

from flask_sqlalchemy import SQLAlchemy

# Global SQLAlchemy instance (initialized in app factory)
db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="user")
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    scans = db.relationship("Scan", back_populates="user", lazy="dynamic")

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email!r} role={self.role!r}>"


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(2048), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="pending")  # pending, running, complete, error
    zap_scan_id = db.Column(db.String(128), nullable=True)

    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)

    risk_score = db.Column(db.Float, nullable=True)
    risk_band = db.Column(db.String(20), nullable=True)  # e.g., "critical", "high", "medium", "low"

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user = db.relationship("User", back_populates="scans")

    findings = db.relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    def __repr__(self) -> str:
        return f"<Scan id={self.id} target_url={self.target_url!r} status={self.status!r}>"


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)

    tool = db.Column(db.String(100), nullable=False)  # e.g., "OWASP ZAP"
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)

    severity = db.Column(
        db.String(20),
        nullable=False,
    )  # expected values: critical, high, medium, low

    cvss = db.Column(db.Float, nullable=True)
    url = db.Column(db.String(2048), nullable=True)

    raw_data = db.Column(db.JSON, nullable=True)

    scan = db.relationship("Scan", back_populates="findings")

    def __repr__(self) -> str:
        return f"<Finding id={self.id} severity={self.severity!r} tool={self.tool!r}>"


def init_db(app):
    """
    Initialize the database with the given Flask app context.

    This will create all tables defined by the models if they do not exist.
    """
    db.init_app(app)
    with app.app_context():
        db.create_all()
