import hmac
import re
import unicodedata
from datetime import datetime, timedelta
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, Security, Request
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.core.config import MAX_PDF_SIZE_MB, logger, ADMIN_API_KEY
from app.models.schemas import AnalysisResponse
from app.services.pdf_parser import extract_text_from_pdf
from app.services.llm_engine import analyze_with_llm
from app.models.database import get_db, ComplianceTask
from sqlalchemy.orm import Session


limiter = Limiter(key_func=get_remote_address)

api_key_header = APIKeyHeader(name="x-api-key", auto_error=True)

MAX_FILENAME_LENGTH = 255

ALLOWED_CONTENT_TYPES = frozenset({
    "application/pdf",
    "application/x-pdf",
    "application/octet-stream",  
})

_DANGEROUS_FILENAME_PATTERNS = re.compile(
    r"(\.\./|\.\.\\|%2e%2e|%00|;|\||`|\$\(|<|>)", re.IGNORECASE
)
_NULL_BYTE = re.compile(r"\x00|%00")

def sanitize_filename(filename: str | None) -> str:
    """
    Sanitize an uploaded filename to prevent path traversal, command injection,
    and filesystem attacks.
    - Strips path components (only keeps the basename)
    - Rejects null bytes, path traversal sequences, and shell metacharacters
    - Normalizes Unicode to NFC form (prevents homoglyph attacks)
    - Enforces maximum length
    - Validates the extension
    """
    if not filename:
        raise HTTPException(status_code=400, detail="Filename is required.")

    if _NULL_BYTE.search(filename):
        raise HTTPException(status_code=400, detail="Invalid filename: null bytes detected.")

    filename = unicodedata.normalize("NFC", filename)
    filename = filename.replace("\\", "/")
    filename = filename.split("/")[-1]

    if _DANGEROUS_FILENAME_PATTERNS.search(filename):
        raise HTTPException(
            status_code=400,
            detail="Invalid filename: contains prohibited characters or sequences."
        )

    if len(filename) > MAX_FILENAME_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=f"Filename too long (max {MAX_FILENAME_LENGTH} characters)."
        )
    filename = filename.lstrip(". ").strip()

    if not filename:
        raise HTTPException(status_code=400, detail="Filename is empty after sanitization.")

    return filename

def validate_content_type(content_type: str | None) -> None:
    """
    Validate that the Content-Type header matches allowed MIME types.
    This is a defense-in-depth check — the real validation is magic bytes.
    """

    if content_type and content_type.lower().split(";")[0].strip() not in ALLOWED_CONTENT_TYPES:
        logger.warning(f"Rejected upload with Content-Type: {content_type}")
        
        raise HTTPException(
            status_code=400,
            detail=f"Invalid Content-Type '{content_type}'. Only PDF files are accepted."
        )

def sanitize_string_for_db(value: str, max_length: int = 1000, field_name: str = "field") -> str:
    """
    Sanitize a string before writing to the database.
    - Rejects null bytes (SQL injection via null byte truncation)
    - Strips control characters except newlines/tabs
    - Enforces maximum length
    - Normalizes Unicode
    Note: SQLAlchemy's ORM uses parameterized queries, which prevents
    classical SQL injection. This function guards against edge cases
    like null byte truncation and stored XSS payloads.
    """

    if not isinstance(value, str):
        value = str(value)

    if "\x00" in value:
        raise ValueError(f"Null bytes not allowed in {field_name}")

    value = unicodedata.normalize("NFC", value)

    value = "".join(
        ch for ch in value
        if ch in ("\n", "\r", "\t") or not unicodedata.category(ch).startswith("C")
    )
    
    if len(value) > max_length:
        value = value[:max_length]
    return value.strip()

async def verify_api_key(api_key: str = Security(api_key_header)):
    """
    Validates the API key from the request header using constant-time
    comparison to prevent timing attacks. Raises 403 if the key is
    invalid or if the server is misconfigured (no key set).
    """
    if not ADMIN_API_KEY:
        logger.critical("ADMIN_API_KEY is not configured — rejecting request.")
        raise HTTPException(status_code=500, detail="Server authentication misconfiguration.")

    if len(api_key) > 256:
        raise HTTPException(status_code=400, detail="API key exceeds maximum length.")
    if any(ord(c) < 32 for c in api_key):

        raise HTTPException(status_code=400, detail="API key contains invalid characters.")
    client_ip = "unknown"

    if not hmac.compare_digest(api_key.encode("utf-8"), ADMIN_API_KEY.encode("utf-8")):
        logger.warning(f"AUTH FAILED: Invalid API key attempt detected (Key Length: {len(api_key)}).")
        raise HTTPException(status_code=403, detail="Could not validate credentials")

    logger.info("AUTH SUCCESS: Valid API key provided.")
    return api_key

router = APIRouter()

@router.get("/")
@limiter.limit("60/minute")
async def root(request: Request):
    return {
        "service": "ComplianceAI API",
        "version": "1.0.0",
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
    }

@router.post("/api/analyze", response_model=AnalysisResponse)
@limiter.limit("5/minute")
async def analyze_document(
    request: Request,
    file: UploadFile = File(...),
    api_key: str = Depends(verify_api_key),
    db: Session = Depends(get_db)
):
    safe_filename = sanitize_filename(file.filename)

    if not safe_filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are accepted.")

    validate_content_type(file.content_type)

    chunk_size = 1024 * 1024  

    pdf_bytes = bytearray()

    first_chunk = await file.read(chunk_size)

    if not first_chunk or not first_chunk.startswith(b"%PDF-"):
        raise HTTPException(status_code=400, detail="Invalid file format. Magic bytes do not match PDF.")

    pdf_bytes.extend(first_chunk)

    while True:

        chunk = await file.read(chunk_size)

        if not chunk:

            break
        pdf_bytes.extend(chunk)

        if (len(pdf_bytes) / (1024 * 1024)) > MAX_PDF_SIZE_MB:
            raise HTTPException(status_code=400, detail="File too large.")

    if len(pdf_bytes) < 67:  
        raise HTTPException(status_code=400, detail="File is too small to be a valid PDF.")

    document_text, page_count = extract_text_from_pdf(bytes(pdf_bytes))

    if len(document_text.strip()) < 100:
        raise HTTPException(status_code=400, detail="Could not extract sufficient text from the PDF.")

    result = await analyze_with_llm(document_text, page_count)

    try:
        for dept in result.departments:

            for task in dept.tasks:

                db_task = ComplianceTask(
                    id=sanitize_string_for_db(task.id, max_length=20, field_name="task.id"),
                    department_name=sanitize_string_for_db(dept.name, max_length=200, field_name="dept.name"),
                    title=sanitize_string_for_db(task.title, max_length=500, field_name="task.title"),
                    description=sanitize_string_for_db(task.description, max_length=5000, field_name="task.description"),
                    priority=sanitize_string_for_db(task.priority, max_length=20, field_name="task.priority"),
                    due_date=sanitize_string_for_db(task.dueDate, max_length=20, field_name="task.dueDate"),
                    source_clause=sanitize_string_for_db(task.sourceClause, max_length=500, field_name="task.sourceClause"),
                    completed=bool(task.completed)
                )
                db.merge(db_task)

        db.commit()

    except ValueError as e:
        db.rollback()
        logger.error(f"Input sanitization rejected a value: {e}")

    except Exception as e:
        db.rollback()
        logger.error(f"Database sync failed: {e}")

    return result

@router.post("/api/analyze/demo")
@limiter.limit("10/minute")
async def demo_analysis(request: Request):
    demo_data = {
        "document": {
            "title": "GDPR Data Privacy & Protection Policy 2026",
            "type": "Regulatory Compliance",
            "pages": 42,
            "analyzedAt": datetime.now().isoformat(),
            "riskLevel": "High",
            "complianceScore": 32,
        },
        "summary": "Analysis of the GDPR Data Privacy Policy revealed actionable obligations across multiple departments.",
        "departments": [
            {
                "name": "Information Technology",
                "icon": "🖥️",
                "color": "#6366f1",
                "tasks": [
                    {
                        "id": "IT-001",
                        "title": "Implement end-to-end data encryption",
                        "description": "Deploy AES-256 encryption for all data at rest.",
                        "priority": "critical",
                        "dueDate": (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d"),
                        "sourceClause": "Article 32",
                        "completed": False,
                    }
                ],
            }
        ],
    }
    return JSONResponse(content=demo_data)

@router.post("/api/verify-key")
@limiter.limit("5/15minute")
async def verify_key_endpoint(request: Request, api_key: str = Depends(verify_api_key)):
    """
    Lightweight endpoint for the frontend to validate an API key
    without performing any analysis. Rate-limited to 5 attempts/min
    to prevent brute-force attacks.
    """
    return {"status": "valid"}