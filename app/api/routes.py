import os
from datetime import datetime, timedelta

from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, Security, Request
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.core.config import MAX_PDF_SIZE_MB, logger
from app.models.schemas import AnalysisResponse
from app.services.pdf_parser import extract_text_from_pdf
from app.services.llm_engine import analyze_with_llm
from app.models.database import get_db, ComplianceTask

# ---------------------------------------------------------------------------
#  Security & Rate Limiting Setup
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address)

API_KEY_NAME = "x-api-key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

async def verify_api_key(api_key: str = Security(api_key_header)):
    # Dynamically pull from environment or fallback to local dev key
    expected_key = os.getenv("ADMIN_API_KEY", "dev-secret-key")
    
    if api_key != expected_key:
        raise HTTPException(
            status_code=403, 
            detail="Could not validate credentials"
        )
    return api_key

# ---------------------------------------------------------------------------
#  API Routes
# ---------------------------------------------------------------------------

router = APIRouter()


@router.get("/")
async def root():
    """Health check endpoint."""
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
    """
    Upload a compliance PDF for AI analysis and store extracted obligations.
    """
    # --- Validate file type ---
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(
            status_code=400,
            detail="Only PDF files are accepted. Please upload a .pdf file."
        )

    if file.content_type and file.content_type != "application/pdf":
        raise HTTPException(
            status_code=400,
            detail=f"Invalid content type: {file.content_type}. Expected application/pdf."
        )

    # --- Safe File Handling (Chunked read & Magic byte check) ---
    chunk_size = 1024 * 1024  # 1MB
    pdf_bytes = bytearray()
    
    first_chunk = await file.read(chunk_size)
    if not first_chunk.startswith(b"%PDF-"):
        raise HTTPException(
            status_code=400, 
            detail="Invalid file format. Magic bytes do not match PDF."
        )
        
    pdf_bytes.extend(first_chunk)

    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
            
        pdf_bytes.extend(chunk)
        
        file_size_mb = len(pdf_bytes) / (1024 * 1024)
        if file_size_mb > MAX_PDF_SIZE_MB:
            raise HTTPException(
                status_code=400,
                detail=f"File too large. Maximum size is {MAX_PDF_SIZE_MB}MB."
            )

    final_size_mb = len(pdf_bytes) / (1024 * 1024)
    logger.info(f"Received PDF: {file.filename} ({final_size_mb:.1f}MB)")

    # --- Step 1: Extract text from PDF ---
    document_text, page_count = extract_text_from_pdf(bytes(pdf_bytes))
    logger.info(f"Extracted {len(document_text)} chars from {page_count} pages")

    if len(document_text.strip()) < 100:
        raise HTTPException(
            status_code=400,
            detail="Could not extract sufficient text from the PDF. "
                   "The file may be image-based (scanned). Please use an OCR tool first."
        )

    # --- Step 2: Analyze with LLM ---
    result = analyze_with_llm(document_text, page_count)

    logger.info(
        f"Analysis complete: {sum(len(d.tasks) for d in result.departments)} tasks "
        f"across {len(result.departments)} departments"
    )

    # --- Step 3: Store Tasks in Database ---
    try:
        saved_count = 0
        for dept in result.departments:
            for task in dept.tasks:
                db_task = ComplianceTask(
                    id=task.id,
                    department_name=dept.name,
                    title=task.title,
                    description=task.description,
                    priority=task.priority,
                    due_date=task.dueDate,
                    source_clause=task.sourceClause,
                    completed=task.completed
                )
                # Using merge() performs an upsert: it updates the row if the ID already exists
                db.merge(db_task)
                saved_count += 1
                
        db.commit()
        logger.info(f"Successfully stored/updated {saved_count} tasks in the database.")
    except Exception as e:
        db.rollback()
        logger.error(f"Database error while saving tasks: {e}")
        # We don't fail the entire request if the DB save fails, but we log it.
        # Alternatively, raise an HTTP 500 here if database persistence is strictly required.

    return result


@router.post("/api/analyze/demo")
async def demo_analysis():
    """
    Returns a hardcoded demo response for testing the frontend
    without requiring an OpenAI API key or a real PDF.
    """
    demo_data = {
        "document": {
            "title": "GDPR Data Privacy & Protection Policy 2026",
            "type": "Regulatory Compliance",
            "pages": 42,
            "analyzedAt": datetime.now().isoformat(),
            "riskLevel": "High",
            "complianceScore": 32,
        },
        "summary": (
            "Analysis of the GDPR Data Privacy & Protection Policy revealed "
            "18 actionable obligations across 5 departments. Critical items "
            "include implementing data encryption, conducting DPIAs, and "
            "establishing a 72-hour breach notification procedure."
        ),
        "departments": [
            {
                "name": "Information Technology",
                "icon": "🖥️",
                "color": "#6366f1",
                "tasks": [
                    {
                        "id": "IT-001",
                        "title": "Implement end-to-end data encryption",
                        "description": "Deploy AES-256 encryption for all personal data at rest and TLS 1.3 for data in transit.",
                        "priority": "critical",
                        "dueDate": (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d"),
                        "sourceClause": "Article 32 — Security of Processing",
                        "completed": False,
                    },
                    {
                        "id": "IT-002",
                        "title": "Deploy automated access control system",
                        "description": "Implement RBAC with MFA for all systems processing personal data.",
                        "priority": "high",
                        "dueDate": (datetime.now() + timedelta(days=45)).strftime("%Y-%m-%d"),
                        "sourceClause": "Article 25 — Data Protection by Design",
                        "completed": False,
                    },
                ],
            },
            {
                "name": "Human Resources",
                "icon": "👥",
                "color": "#f59e0b",
                "tasks": [
                    {
                        "id": "HR-001",
                        "title": "Conduct mandatory GDPR training for all staff",
                        "description": "Roll out organization-wide data protection training.",
                        "priority": "high",
                        "dueDate": (datetime.now() + timedelta(days=60)).strftime("%Y-%m-%d"),
                        "sourceClause": "Article 39(1)(b) — Tasks of the DPO",
                        "completed": False,
                    },
                ],
            },
            {
                "name": "Legal & Compliance",
                "icon": "⚖️",
                "color": "#a78bfa",
                "tasks": [
                    {
                        "id": "LEG-001",
                        "title": "Appoint a Data Protection Officer",
                        "description": "Formally designate a qualified DPO and register with the supervisory authority.",
                        "priority": "critical",
                        "dueDate": (datetime.now() + timedelta(days=15)).strftime("%Y-%m-%d"),
                        "sourceClause": "Articles 37-39 — Data Protection Officer",
                        "completed": False,
                    },
                ],
            },
        ],
    }
    return JSONResponse(content=demo_data)