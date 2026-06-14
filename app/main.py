"""
ComplianceAI — Document-to-Action Agent Backend
================================================
Application entry point: initializes the FastAPI app, configures
CORS middleware, and wires up the API router.

Run:
    uvicorn app.main:app --reload --port 8000

Architecture:
    1. PDF Upload  →  PyMuPDF text extraction
    2. Text chunks →  LLM (OpenAI GPT-4o) with structured system prompt
    3. LLM output  →  Strict JSON parsed into Pydantic models
    4. JSON response →  Returned to the frontend dashboard
"""

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler

from app.api.routes import router, limiter
from app.models.database import engine, Base

# ---------------------------------------------------------------------------
#  Database Initialization
# ---------------------------------------------------------------------------

# Ensure all defined tables are created in the database upon startup.
# In a production setting, you would likely replace this with Alembic migrations.
Base.metadata.create_all(bind=engine)


# ---------------------------------------------------------------------------
#  FastAPI App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="ComplianceAI API",
    description="Document-to-Action Agent for Compliance",
    version="1.0.0",
)

# Attach SlowAPI Rate Limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS — Restrict origins to explicitly trusted frontend URLs
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:5500"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom Middleware — Strict HTTP Security Headers
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# ---------------------------------------------------------------------------
#  Routes
# ---------------------------------------------------------------------------

app.include_router(router)


# ---------------------------------------------------------------------------
#  Run with: uvicorn app.main:app --reload --port 8000
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)