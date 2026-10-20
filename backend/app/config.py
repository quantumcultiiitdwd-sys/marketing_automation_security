import os


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).lower() in ("1", "true", "yes")


class Settings:
    env = os.getenv("APP_ENV", "development")
    database_url = os.getenv("DATABASE_URL", "sqlite:///./campaignshield.db")
    secret_key = os.getenv("SECRET_KEY", "dev-insecure-secret-change-me-0123456789abcdef")
    # Fernet key (urlsafe base64, 32 bytes). Injected from the secret manager in production.
    encryption_key = os.getenv("ENCRYPTION_KEY", "")
    session_hours = int(os.getenv("SESSION_HOURS", "12"))
    public_api_url = os.getenv("PUBLIC_API_URL", "http://localhost:8000")
    public_app_url = os.getenv("PUBLIC_APP_URL", "http://localhost:3000")
    cors_origins = [o for o in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",") if o]
    allow_private_hosts = _bool("ALLOW_PRIVATE_INTEGRATION_HOSTS", env == "development")
    demo_enabled = _bool("DEMO_ENABLED", True)
    monitor_interval_seconds = int(os.getenv("MONITOR_INTERVAL_SECONDS", "300"))
    rate_limit_per_minute = int(os.getenv("RATE_LIMIT_PER_MINUTE", "600"))
    google_client_id = os.getenv("GOOGLE_OAUTH_CLIENT_ID", "")
    google_client_secret = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", "")
    google_ads_developer_token = os.getenv("GOOGLE_ADS_DEVELOPER_TOKEN", "")
    google_ads_api_version = os.getenv("GOOGLE_ADS_API_VERSION", "v21")
    sentry_dsn = os.getenv("SENTRY_DSN", "")
    # Cloudflare Turnstile on sign-in/sign-up. Enabled when the secret is set.
    turnstile_sitekey = os.getenv("TURNSTILE_SITEKEY", "")
    turnstile_secret = os.getenv("TURNSTILE_SECRET", "")
    turnstile_hostnames = {h.strip() for h in os.getenv("TURNSTILE_HOSTNAMES", "").split(",") if h.strip()}

    def validate(self):
        if self.env == "production":
            missing = [n for n in ("SECRET_KEY", "ENCRYPTION_KEY") if not os.getenv(n)]
            if missing:
                raise RuntimeError(f"Missing required production secrets: {', '.join(missing)}")
            if self.database_url.startswith("sqlite"):
                raise RuntimeError("Production requires PostgreSQL (DATABASE_URL)")
            if self.turnstile_secret:
                if not self.turnstile_sitekey or not self.turnstile_hostnames:
                    raise RuntimeError("TURNSTILE_SECRET requires TURNSTILE_SITEKEY and TURNSTILE_HOSTNAMES")
                if self.turnstile_hostnames & {"localhost", "127.0.0.1"} or self.turnstile_secret[:2] in ("1x", "2x", "3x"):
                    raise RuntimeError("Production Turnstile must not use localhost hostnames or Cloudflare test keys")


settings = Settings()
