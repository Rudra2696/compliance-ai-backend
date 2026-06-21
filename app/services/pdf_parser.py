import fitz  
from fastapi import HTTPException
from app.core.config import MAX_TEXT_CHARS, logger

MAX_PAGES = 5000

def extract_text_from_pdf(pdf_bytes: bytes) -> tuple[str, int]:
    
    """
    Extract all text from a PDF using PyMuPDF (fitz).
    Returns:
        tuple of (extracted_text, page_count)
    Security measures:
        - Page count cap to prevent DoS via artificially inflated PDFs
        - Text length truncation for LLM context window safety
        - Error messages never expose internal paths or stack traces
        - PyMuPDF runs in-memory (no temp files on disk)
    Why PyMuPDF?
        - Pure C library → extremely fast (10-100x faster than pdfplumber)
        - No Java dependency (unlike Tika or Tabula)
        - Handles complex layouts, scanned-text layers, and Unicode well
        - Small footprint, ideal for hackathon/serverless deployments
    """

    try:

        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        

    except Exception as e:

        logger.error(f"PDF failed to open: {type(e).__name__}")

        raise HTTPException(
            status_code=400,
            detail="The uploaded file could not be opened as a valid PDF. Please verify the file is not corrupted."
        )
    
    try:

        page_count = len(doc)
        if page_count > MAX_PAGES:
            doc.close()

            raise HTTPException(
                status_code=400,
                detail=f"PDF has {page_count} pages, which exceeds the maximum of {MAX_PAGES}."
            )
        
        text_parts = []

        for page_num, page in enumerate(doc):

            try:

                page_text = page.get_text("text")
                
                if page_text.strip():
                    text_parts.append(f"--- Page {page_num + 1} ---\n{page_text}")

            except Exception as e:

                logger.warning(f"Failed to extract text from page {page_num + 1}: {type(e).__name__}")

                continue

        doc.close()

        full_text = "\n\n".join(text_parts)

        full_text = full_text.replace("\x00", "")

        if len(full_text) > MAX_TEXT_CHARS:

            logger.warning(
                f"PDF text truncated from {len(full_text)} to {MAX_TEXT_CHARS} chars"
            )

            full_text = full_text[:MAX_TEXT_CHARS] + "\n\n[... truncated for processing ...]"
            
        return full_text, page_count
    
    except HTTPException:

        raise

    except Exception as e:

        logger.error(f"PDF text extraction failed: {type(e).__name__}")

        try:

            doc.close()

        except Exception:
            pass
        
        raise HTTPException(
            status_code=400,
            detail="Failed to extract text from the PDF. The file may be corrupted or password-protected."
        )
