import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from a .env file if present
load_dotenv()


class Config:
    """Base configuration for DissoFinito backend."""

    # Core Flask settings
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-jwt-secret-key-change-me")

    # Database: SQLite in instance/dissofinito.db
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    INSTANCE_DIR = os.path.join(os.path.dirname(BASE_DIR), "instance")
    os.makedirs(INSTANCE_DIR, exist_ok=True)

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(INSTANCE_DIR, 'dissofinito.db')}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT configuration (placeholders, can be adjusted later)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_TOKEN_LOCATION = ["headers"]
    JWT_HEADER_NAME = "Authorization"
    JWT_HEADER_TYPE = "Bearer"

    # OWASP ZAP settings placeholders
    ZAP_API_KEY = os.getenv("ZAP_API_KEY", "changeme-zap-api-key")
    ZAP_API_URL = os.getenv("ZAP_API_URL", "http://localhost:8080")

    # CORS / frontend integration
    FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")
