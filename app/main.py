import time
import os
import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
from app.api.routes import router, limiter
from app.core.config import validate_security_config, logger, ALLOWED_ORIGINS
validate_security_config()

app = FastAPI(
    title="ComplianceAI API",
    description="Document-to-Action Agent for Compliance",
    version="1.0.0",
    docs_url=None if os.getenv("ENVIRONMENT") == "production" else "/docs",
    redoc_url=None if os.getenv("ENVIRONMENT") == "production" else "/redoc",
)

app.state.limiter = limiter

def custom_rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):

    client_ip = request.client.host if request.client else "unknown"

    logger.warning(f"Rate limit exceeded by IP: {client_ip} on path: {request.url.path}")

    return _rate_limit_exceeded_handler(request, exc)

app.add_exception_handler(RateLimitExceeded, custom_rate_limit_exceeded_handler)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):

    client_ip = request.client.host if request.client else "unknown"

    logger.exception(f"UNHANDLED EXCEPTION on {request.method} {request.url.path} from IP: {client_ip}")

    return JSONResponse(
        status_code=500,
        content={"detail": "Something went wrong. Please try again later."}
    )

if os.getenv("ENFORCE_HTTPS", "False").lower() == "true":

    app.add_middleware(HTTPSRedirectMiddleware)

app.add_middleware(
    TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "*.devdynasty.local"]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["x-api-key", "Content-Type"],
)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    
    start_time = time.time()

    client_ip = request.client.host if request.client else "unknown"

    try:
        response = await call_next(request)
        process_time = (time.time() - start_time) * 1000
        log_msg = f"{client_ip} - {request.method} {request.url.path} - Status: {response.status_code} - {process_time:.2f}ms"

        if response.status_code >= 500:
            logger.error(log_msg)

        elif response.status_code >= 400:
            logger.warning(log_msg)

        else:
            logger.info(log_msg)
        return response
    
    except Exception as e:

        process_time = (time.time() - start_time) * 1000
        logger.error(f"{client_ip} - {request.method} {request.url.path} - UNHANDLED EXCEPTION: {e} - {process_time:.2f}ms")

        raise
@app.middleware("http")
async def add_security_headers(request: Request, call_next):

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-XSS-Protection"] = "0"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )

    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=()"
    )

    if request.url.path.startswith("/api/"):

        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"

    if "server" in response.headers:
        del response.headers["server"]
    return response

app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)