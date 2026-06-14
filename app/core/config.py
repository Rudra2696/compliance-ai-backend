import os
import logging

# ---------------------------------------------------------------------------
#  Configuration
# ---------------------------------------------------------------------------

# Set your xAI API key as an environment variable:
#   export XAI_API_KEY="xai-..."
XAI_API_KEY = os.getenv("XAI_API_KEY", "")
XAI_MODEL = os.getenv("XAI_MODEL", "grok-beta")
MAX_PDF_SIZE_MB = 50
MAX_TEXT_CHARS = 80_000  # Truncate very large PDFs to fit context window

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("compliance_ai")
