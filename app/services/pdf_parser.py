import fitz  # PyMuPDF — lightweight, fast PDF text extraction
from fastapi import HTTPException

from app.core.config import MAX_TEXT_CHARS, logger

# ---------------------------------------------------------------------------
#  PDF Text Extraction (using PyMuPDF / fitz)
# ---------------------------------------------------------------------------

def extract_text_from_pdf(pdf_bytes: bytes) -> tuple[str, int]:
    """
    Extract all text from a PDF using PyMuPDF (fitz).

    Returns:
        tuple of (extracted_text, page_count)

    Why PyMuPDF?
        - Pure C library → extremely fast (10-100x faster than pdfplumber)
        - No Java dependency (unlike Tika or Tabula)
        - Handles complex layouts, scanned-text layers, and Unicode well
        - Small footprint, ideal for hackathon/serverless deployments
    """
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        page_count = len(doc)
        text_parts = []

        for page_num, page in enumerate(doc):
            page_text = page.get_text("text")
            if page_text.strip():
                text_parts.append(f"--- Page {page_num + 1} ---\n{page_text}")

        doc.close()
        full_text = "\n\n".join(text_parts)

        # Truncate if text is too long for the LLM context window
        if len(full_text) > MAX_TEXT_CHARS:
            logger.warning(
                f"PDF text truncated from {len(full_text)} to {MAX_TEXT_CHARS} chars"
            )
            full_text = full_text[:MAX_TEXT_CHARS] + "\n\n[... truncated for processing ...]"

        return full_text, page_count

    except Exception as e:
        logger.error(f"PDF extraction failed: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to extract text from PDF: {str(e)}")
