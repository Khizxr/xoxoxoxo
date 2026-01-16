import os
from functools import wraps
from typing import Any, Dict, List, Tuple
from risk_scoring import compute_risk_score, severity_counts

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
    verify_jwt_in_request,
)
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config
from models import db, init_db, User, Scan, Finding
from zap_client import start_active_scan, get_scan_status, fetch_alerts  # type: ignore[import]


jwt = JWTManager()


def create_admin_if_missing(app: Flask):
    """
    Ensure there is at least one admin user with:
    email: admin@example.com
    password: password123
    role: admin
    """
    with app.app_context():
        admin_email = "admin@example.com"
        existing = User.query.filter_by(email=admin_email).first()
        if existing is None:
            admin = User(
                email=admin_email,
                password_hash=generate_password_hash("password123"),
                role="admin",
            )
            db.session.add(admin)
            db.session.commit()


def scan_to_dict(scan: Scan, include_stats: bool = False) -> Dict[str, Any]:
    data: Dict[str, Any] = {
        "id": scan.id,
        "target_url": scan.target_url,
        "status": scan.status,
        "zap_scan_id": scan.zap_scan_id,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "risk_score": scan.risk_score,
        "risk_band": scan.risk_band,
        "user_id": scan.user_id,
    }

    if include_stats:
        counts = severity_counts(scan.findings)
        data["severity_counts"] = counts

    return data



def finding_to_dict(finding: Finding) -> Dict[str, Any]:
    """Serialize Finding model instance to a JSON-serializable dict."""
    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "tool": finding.tool,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "cvss": finding.cvss,
        "url": finding.url,
        "raw_data": finding.raw_data,
    }


def normalize_zap_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map a ZAP alert JSON object into fields for the Finding model.

    Expected ZAP fields (may vary by version): 'alert', 'description', 'risk', 'url', 'tags', 'solution', etc.[web:69]
    """
    # Title and description
    title = alert.get("alert") or alert.get("name") or "ZAP Alert"
    description_parts: List[str] = []
    for key in ("description", "otherinfo", "solution", "reference"):
        val = alert.get(key)
        if val:
            description_parts.append(f"{key.capitalize()}: {val}")
    description = "\n\n".join(description_parts) if description_parts else "No description provided."

    # Severity mapping
    risk = (alert.get("risk") or alert.get("riskString") or "").lower()
    severity = "low"
    if risk == "high":
        severity = "high"
    elif risk == "medium":
        severity = "medium"
    elif risk == "low":
        severity = "low"
    elif risk == "informational":
        severity = "low"

    # CVSS from tags if available
    cvss_score: float | None = None
    tags = alert.get("tags") or {}
    if isinstance(tags, dict):
        # Common tag keys sometimes used in reports for CVSS.[web:69]
        for k, v in tags.items():
            if "cvss" in str(k).lower():
                try:
                    cvss_score = float(str(v).split()[0])
                    break
                except (ValueError, TypeError):
                    continue
    if cvss_score is None:
        cvss_score = 0.0

    url = alert.get("url") or alert.get("uri")

    return {
        "title": title,
        "description": description,
        "severity": severity,
        "cvss": cvss_score,
        "url": url,
        "raw_data": alert,
    }


def compute_risk_score(findings: List[Finding]) -> Tuple[float, str]:
    """
    Simple placeholder risk scoring function.

    Assigns weights per severity and computes a normalized score in [0, 100],
    then maps it to a band: critical, high, medium, low.
    """
    weights = {
        "critical": 5,
        "high": 3,
        "medium": 2,
        "low": 1,
    }
    total = 0
    for f in findings:
        sev = (f.severity or "").lower()
        total += weights.get(sev, 1)

    # Simple normalization: assume 20 findings at max weight would be "100"
    max_score = 20 * weights["critical"]
    score = 0.0
    if max_score > 0:
        score = min(100.0, (total / max_score) * 100.0)

    if score >= 80:
        band = "critical"
    elif score >= 60:
        band = "high"
    elif score >= 40:
        band = "medium"
    else:
        band = "low"

    return score, band


def create_app(config_class: type = Config) -> Flask:
    """
    Application factory for DissoFinito backend.
    """
    app = Flask(__name__, instance_relative_config=True)

    # Load configuration
    app.config.from_object(config_class)

    # Ensure instance folder exists (for SQLite DB etc.)
    try:
        os.makedirs(app.instance_path, exist_ok=True)
    except OSError:
        pass

    # Initialize extensions
    CORS(
        app,
        resources={r"/api/*": {"origins": app.config.get("FRONTEND_ORIGIN", "*")}},
        supports_credentials=True,
    )

    jwt.init_app(app)
    init_db(app)

    # Ensure default admin exists
    create_admin_if_missing(app)

    # JWT decorator for role-based protection
    def jwt_required_role(required_role=None):
        """
        Decorator enforcing that a valid JWT is present.
        Optionally checks for a specific user role in the database.
        """

        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                verify_jwt_in_request()
                user_id = get_jwt_identity()
                user = User.query.get(user_id)
                if user is None:
                    return jsonify({"msg": "User not found"}), 404
                if required_role is not None and user.role != required_role:
                    return jsonify({"msg": "Forbidden"}), 403
                return fn(*args, **kwargs)

            return wrapper

        return decorator

    # Health check endpoint
    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok"})

    # Auth: login route
    @app.route("/api/auth/login", methods=["POST"])
    def login():
        if not request.is_json:
            return jsonify({"msg": "Missing JSON in request"}), 400

        data = request.get_json() or {}
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"msg": "Email and password are required"}), 400

        user = User.query.filter_by(email=email).first()
        if user is None or not check_password_hash(user.password_hash, password):
            return jsonify({"msg": "Invalid email or password"}), 401

        access_token = create_access_token(identity=user.id)
        user_payload = {
            "id": user.id,
            "email": user.email,
            "role": user.role,
        }

        return jsonify({"access_token": access_token, "user": user_payload}), 200

    # Auth: current user endpoint
    @app.route("/api/auth/me", methods=["GET"])
    @jwt_required()
    def me():
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if user is None:
            return jsonify({"msg": "User not found"}), 404

        return (
            jsonify(
                {
                    "id": user.id,
                    "email": user.email,
                    "role": user.role,
                }
            ),
            200,
        )

    # Scans: create and start ZAP scan
    @app.route("/api/scans", methods=["POST"])
    @jwt_required()
    def create_scan():
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if user is None:
            return jsonify({"msg": "User not found"}), 404

        if not request.is_json:
            return jsonify({"msg": "Missing JSON in request"}), 400

        data = request.get_json() or {}
        target_url = data.get("target_url")
        if not target_url:
            return jsonify({"msg": "target_url is required"}), 400

        scan = Scan(
            target_url=target_url,
            status="pending",
            user_id=user.id,
        )
        db.session.add(scan)
        db.session.commit()

        try:
            zap_scan_id = start_active_scan(
                target_url=target_url,
                config=app.config,
            )
        except Exception as exc:
            scan.status = "error"
            db.session.commit()
            return jsonify({"msg": "Failed to start scan", "error": str(exc)}), 500

        scan.zap_scan_id = zap_scan_id
        from datetime import datetime

        scan.status = "running"
        scan.started_at = datetime.utcnow()
        db.session.commit()

        return jsonify(scan_to_dict(scan)), 201

    # Scans: refresh status and ingest findings when complete
    @app.route("/api/scans/<int:scan_id>/refresh", methods=["POST"])
    @jwt_required()
    def refresh_scan(scan_id: int):
        user_id = get_jwt_identity()
        scan = Scan.query.get(scan_id)
        if scan is None or scan.user_id != user_id:
            return jsonify({"msg": "Scan not found"}), 404

        if scan.status != "running":
            # Nothing to do; just return current state with stats
            return jsonify(scan_to_dict(scan, include_stats=True)), 200

        if not scan.zap_scan_id:
            return jsonify({"msg": "Scan has no associated ZAP scan id"}), 400

        try:
            status = get_scan_status(scan.zap_scan_id, app.config)
        except Exception as exc:
            return jsonify({"msg": "Failed to query scan status", "error": str(exc)}), 500

        if status < 100:
            # Still running
            return jsonify({"status": status, **scan_to_dict(scan, include_stats=True)}), 200

        # Scan is complete: fetch alerts and store findings
        try:
            alerts = fetch_alerts(scan.target_url, app.config)
        except Exception as exc:
            scan.status = "error"
            db.session.commit()
            return jsonify({"msg": "Failed to fetch alerts", "error": str(exc)}), 500

        # Clear existing findings if any
        for f in scan.findings:
            db.session.delete(f)

        findings_models: List[Finding] = []
        for alert in alerts:
            normalized = normalize_zap_alert(alert)
            finding = Finding(
                scan_id=scan.id,
                tool="OWASP ZAP",
                title=normalized["title"],
                description=normalized["description"],
                severity=normalized["severity"],
                cvss=normalized["cvss"],
                url=normalized["url"],
                raw_data=normalized["raw_data"],
            )
            db.session.add(finding)
            findings_models.append(finding)

        from datetime import datetime

        scan.status = "complete"
        scan.finished_at = datetime.utcnow()

        score, band = compute_risk_score(findings_models)
        scan.risk_score = score
        scan.risk_band = band

        db.session.commit()

        return jsonify(scan_to_dict(scan, include_stats=True)), 200

    # Scans: list scans for current user
    @app.route("/api/scans", methods=["GET"])
    @jwt_required()
    def list_scans():
        user_id = get_jwt_identity()
        scans = (
            Scan.query.filter_by(user_id=user_id)
            .order_by(Scan.started_at.desc().nullslast())
            .all()
        )
        return jsonify([scan_to_dict(s) for s in scans]), 200

    # Scans: get single scan with severity stats
    @app.route("/api/scans/<int:scan_id>", methods=["GET"])
    @jwt_required()
    def get_scan(scan_id: int):
        user_id = get_jwt_identity()
        scan = Scan.query.get(scan_id)
        if scan is None or scan.user_id != user_id:
            return jsonify({"msg": "Scan not found"}), 404

        return jsonify(scan_to_dict(scan, include_stats=True)), 200

    # Scans: list findings for a scan
    @app.route("/api/scans/<int:scan_id>/findings", methods=["GET"])
    @jwt_required()
    def list_findings(scan_id: int):
        user_id = get_jwt_identity()
        scan = Scan.query.get(scan_id)
        if scan is None or scan.user_id != user_id:
            return jsonify({"msg": "Scan not found"}), 404

        findings = scan.findings.order_by(Finding.severity.desc()).all()
        return jsonify([finding_to_dict(f) for f in findings]), 200

    # Expose decorator via app for easy import elsewhere
    app.jwt_required_role = jwt_required_role  # type: ignore[attr-defined]

    return app


if __name__ == "__main__":
    application = create_app()
    application.run(host="0.0.0.0", port=5000, debug=True)
