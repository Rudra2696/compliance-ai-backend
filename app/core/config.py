import os
import sys
import logging
from dotenv import load_dotenv

load_dotenv()

XAI_API_KEY = os.getenv("XAI_API_KEY", "")

XAI_MODEL = os.getenv("XAI_MODEL", "meta-llama/llama-4-scout-17b-16e-instruct")

XAI_BASE_URL = os.getenv("XAI_BASE_URL", "https://api.groq.com/openai/v1")

MAX_PDF_SIZE_MB = 25

MAX_TEXT_CHARS = 80_000  

_raw_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:5500")

ALLOWED_ORIGINS = [origin.strip() for origin in _raw_origins.split(",") if origin.strip()]

logging.basicConfig(level=logging.INFO)

logger = logging.getLogger("compliance_ai")

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")

_WEAK_KEYS = frozenset({
    "",
    "dev-secret-key",
    "super-secret-production-key",
    "changeme",
    "password",
    "secret",
    "admin",
    "test",
})

def validate_security_config() -> None:
    """

    Validates that critical security settings are properly configured.
    Called once at application startup. Refuses to start if the
    ADMIN_API_KEY is missing or matches a known weak default.
    """

    if ADMIN_API_KEY in _WEAK_KEYS:

        logger.critical(
            "FATAL: ADMIN_API_KEY is missing or set to a known weak default. "
            "Generate a strong key with: python -c \"import secrets; print(secrets.token_urlsafe(48))\" "
            "and set it in your .env file."
        )
        sys.exit(1)
        
    if len(ADMIN_API_KEY) < 32:
        logger.warning(
            "WARNING: ADMIN_API_KEY is shorter than 32 characters. "
            "Consider using a longer key for production deployments."
        )
        
    logger.info("Security configuration validated successfully.")
