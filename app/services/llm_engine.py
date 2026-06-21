import json
from datetime import datetime, timedelta
import re
import asyncio
import os
import unicodedata
from fastapi import HTTPException
from openai import AsyncOpenAI
from app.core.config import XAI_MODEL, XAI_BASE_URL, logger
from app.models.schemas import AnalysisResponse


SYSTEM_PROMPT = """You are ComplianceAI, an expert regulatory compliance analyst. You must analyze text and extract obligations.
You MUST respond with a single, valid JSON object matching this structure exactly. Do not include markdown code fences or explanations.
Target JSON Format:
{
  "document": {
    "title": "Clean Title of the Policy",
    "type": "Regulatory Compliance",
    "pages": 0,
    "analyzedAt": "",
    "riskLevel": "High",
    "complianceScore": 50
  },
  "summary": "2-3 sentence executive summary here.",
  "departments": [
    {
      "name": "Information Technology",
      "icon": "🖥️",
      "color": "#6366f1",
      "tasks": [
        {
          "id": "IT-001",
          "title": "Actionable task title",
          "description": "Detailed description of what to do.",
          "priority": "critical",
          "dueDate": "2026-09-01",
          "sourceClause": "Article 32",
          "completed": false
        }
      ]
    }
  ]
}

Strict Rules:
1. You must use EXACTLY these field names: 'document', 'summary', 'departments', 'name', 'icon', 'color', 'tasks', 'id', 'title', 'description', 'priority', 'dueDate', 'sourceClause', 'completed'. 
2. The 'dueDate' MUST be a clean string in 'YYYY-MM-DD' format. If NO specific calendar deadline is explicitly written in the document text, you MUST output exactly the word "None". DO NOT invent, guess, or calculate dates.
3. The 'priority' field must be exactly 'critical', 'high', 'medium', or 'low'.
4. The 'completed' field must be false.
"""

raw_keys = os.getenv("XAI_API_KEY", "")

API_KEYS = [k.strip() for k in raw_keys.split(",") if k.strip()]

_SCRIPT_INJECTION_PATTERN = re.compile(
    r"<\s*script|javascript\s*:|on\w+\s*=|<\s*iframe|<\s*object|<\s*embed|<\s*link|"
    r"<\s*img\s[^>]*\bonerror\b|expression\s*\(|vbscript\s*:|data\s*:\s*text/html",
    re.IGNORECASE
)

_STRIP_CATEGORIES = {"Cc", "Cf", "Cs", "Co"}

_KEEP_CHARS = {"\n", "\r", "\t"}

def sanitize_llm_string(value, max_length: int = 1000, field_name: str = "field") -> str:

    """
    Sanitize a single string value from LLM output.
    Defense layers:
    1. Type coercion (ensure it's actually a string)
    2. Null byte rejection
    3. Unicode normalization (NFC)
    4. Control character stripping
    5. Script injection pattern detection
    6. Length enforcement
    7. Whitespace normalization
    """

    if value is None:
        return ""
    
    if not isinstance(value, str):
        value = str(value)

    if "\x00" in value:
        logger.warning(f"Null byte detected in LLM output field '{field_name}', stripping.")
        value = value.replace("\x00", "")

    value = unicodedata.normalize("NFC", value)
    
    value = "".join(
        ch for ch in value
        if ch in _KEEP_CHARS or unicodedata.category(ch) not in _STRIP_CATEGORIES
    )

    if _SCRIPT_INJECTION_PATTERN.search(value):
        logger.warning(
            f"Script injection pattern detected in LLM output field '{field_name}'. "
            f"Neutralizing payload."
        )
        value = value.replace("<", "&lt;").replace(">", "&gt;")
        
    if len(value) > max_length:
        logger.warning(
            f"LLM output field '{field_name}' truncated from {len(value)} to {max_length} chars."
        )
        value = value[:max_length]

    return value.strip()

def sanitize_llm_int(value, default: int = 0, min_val: int = 0, max_val: int = 100) -> int:
    
    """Safely coerce LLM output to a bounded integer."""

    if isinstance(value, dict):
        value = next(iter(value.values()), default)

    try:
        result = int(value)
        return max(min_val, min(result, max_val))
    
    except (ValueError, TypeError):
        return default
    
def clean_llm_json(data: dict) -> dict:
    """
    Sanitize and normalize raw LLM JSON output into a clean structure
    that matches our Pydantic schemas. Every string is sanitized,
    every number is bounded, and every enum is validated.
    """

    if not isinstance(data, dict):
        logger.error(f"LLM returned non-dict type: {type(data)}")
        return {"document": {}, "departments": []}
    doc_raw = data.get("document", {})

    if not isinstance(doc_raw, dict):
        doc_raw = {}
    risk_level = sanitize_llm_string(
        doc_raw.get("riskLevel") or doc_raw.get("risklevel") or "Medium",
        max_length=20, field_name="document.riskLevel"
    ).capitalize()

    if risk_level not in ("Low", "Medium", "High", "Critical"):
        risk_level = "High"
    cleaned = {
        "document": {
            "title": sanitize_llm_string(
                doc_raw.get("title") or doc_raw.get("documentTitle") or "Compliance Policy Document",
                max_length=500, field_name="document.title"
            ),
            "type": sanitize_llm_string(
                doc_raw.get("type") or doc_raw.get("documentType") or "Regulatory Compliance",
                max_length=200, field_name="document.type"
            ),
            "pages": 0,
            "analyzedAt": "",
            "riskLevel": risk_level,
            "complianceScore": sanitize_llm_int(
                doc_raw.get("complianceScore") or doc_raw.get("riskScore") or 50,
                default=50, min_val=0, max_val=100
            )
        },
        "summary": sanitize_llm_string(
            data.get("summary") or data.get("executiveSummary") or "Analysis complete.",
            max_length=10000, field_name="summary"
        ),
        "departments": []
    }

    raw_depts = data.get("departments") or data.get("complianceObligations") or []

    if not isinstance(raw_depts, list):
        raw_depts = []

    for idx, d in enumerate(raw_depts[:50]):
        if not isinstance(d, dict):
            continue
        
        dept_name = sanitize_llm_string(
            d.get("name") or d.get("departmentName") or f"Operations Group {idx+1}",
            max_length=200, field_name=f"departments[{idx}].name"
        )

        dept_icon = sanitize_llm_string(
            d.get("icon") or d.get("departmentIcon") or "📋",
            max_length=10, field_name=f"departments[{idx}].icon"
        )

        dept_color = sanitize_llm_string(
            d.get("color") or d.get("hexColor") or d.get("departmentHexColor") or "#6366f1",
            max_length=20, field_name=f"departments[{idx}].color"
        )

        if not re.match(r"^#[0-9a-fA-F]{3,8}$", dept_color):
            dept_color = "#6366f1"

        cleaned_tasks = []

        raw_tasks = d.get("tasks") or d.get("obligations") or []

        if not isinstance(raw_tasks, list):
            raw_tasks = []

        for t_idx, t in enumerate(raw_tasks[:100]):

            if not isinstance(t, dict):
                continue

            raw_date = sanitize_llm_string(
                t.get("dueDate") or t.get("duedate") or "",
                max_length=20, field_name=f"task[{t_idx}].dueDate"
            )

            if raw_date.lower() == "none":
                raw_date = ""

            if raw_date and not re.match(r"^\d{4}-\d{2}-\d{2}$", raw_date):
                raw_date = ""
            priority = sanitize_llm_string(
                t.get("priority") or "medium",
                max_length=20, field_name=f"task[{t_idx}].priority"
            ).lower()

            if priority not in ("critical", "high", "medium", "low"):
                priority = "medium"
            task_id = sanitize_llm_string(
                t.get("id") or t.get("taskID") or f"TASK-{idx+1:03d}",
                max_length=20, field_name=f"task[{t_idx}].id"
            )
            task_id = re.sub(r"[^A-Za-z0-9\-]", "", task_id)

            if not task_id:
                task_id = f"TASK-{idx+1:03d}"
            cleaned_tasks.append({
                "id": task_id,
                "title": sanitize_llm_string(
                    t.get("title") or t.get("taskTitle") or "Compliance Requirement",
                    max_length=500, field_name=f"task[{t_idx}].title"
                ),
                "description": sanitize_llm_string(
                    t.get("description") or t.get("taskDescription") or "No further description provided.",
                    max_length=5000, field_name=f"task[{t_idx}].description"
                ),
                "priority": priority,
                "dueDate": raw_date,
                "sourceClause": sanitize_llm_string(
                    t.get("sourceClause") or t.get("sourceReference") or "General Terms",
                    max_length=500, field_name=f"task[{t_idx}].sourceClause"
                ),
                "completed": False
            })

        cleaned["departments"].append({
            "name": dept_name,
            "icon": dept_icon,
            "color": dept_color,
            "tasks": cleaned_tasks
        })

    return cleaned

def chunk_text(text: str, chunk_size_chars: int = 14000) -> list[str]:

    words = text.split()

    chunks = []

    current_chunk = []

    current_length = 0

    for word in words:

        if current_length + len(word) > chunk_size_chars:
            chunks.append(" ".join(current_chunk))
            current_chunk = [word]
            current_length = len(word)

        else:
            current_chunk.append(word)
            current_length += len(word) + 1 

    if current_chunk:
        chunks.append(" ".join(current_chunk))

    return chunks

async def process_single_chunk(chunk: str, chunk_index: int, total_chunks: int, api_key: str, today: str) -> dict:
    """Worker function that handles a single chunk with a specific API key concurrently."""
    client = AsyncOpenAI(api_key=api_key, base_url=XAI_BASE_URL)
    user_message = f"Today's date is {today}. Analyzing Part {chunk_index+1} of {total_chunks}.\n\nDOCUMENT TEXT:\n\n{chunk}"

    try:
        response = await client.chat.completions.create(
            model=XAI_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            temperature=0.1,       
            max_tokens=8000,       
            response_format={"type": "json_object"},  
        )
        raw_content = response.choices[0].message.content

        if response.usage:
            logger.info(f"Chunk {chunk_index+1} Token Usage: {response.usage.total_tokens} total tokens (Prompt: {response.usage.prompt_tokens}, Completion: {response.usage.completion_tokens})")

        try:
            parsed = json.loads(raw_content)

        except json.JSONDecodeError as e:
            logger.error(f"Chunk {chunk_index+1}: LLM returned invalid JSON: {e}")
            return {"departments": [], "document": {}}
        
        if not isinstance(parsed, dict):
            logger.error(f"Chunk {chunk_index+1}: LLM returned non-dict JSON type: {type(parsed)}")
            return {"departments": [], "document": {}}
        
        return clean_llm_json(parsed)
    
    except Exception as e:
        logger.error(f"Chunk {chunk_index+1} failed with key ending in ...{api_key[-4:]}: {e}")
        return {"departments": [], "document": {}}
    
async def analyze_with_llm(document_text: str, page_count: int) -> AnalysisResponse:

    if not API_KEYS:
        raise HTTPException(status_code=500, detail="No API Keys configured. Please add keys to your .env file.")
    
    today = datetime.now().strftime("%Y-%m-%d")

    text_chunks = chunk_text(document_text)

    logger.info(f"Split document into {len(text_chunks)} chunks. Processing in parallel using {len(API_KEYS)} keys.")
   
    master_data = {
        "document": {
            "title": "Compliance Analysis Report",
            "type": "Regulatory Document",
            "pages": page_count,
            "analyzedAt": datetime.now().isoformat(),
            "riskLevel": "Medium",
            "complianceScore": 50
        },
        "summary": "Comprehensive analysis across all document sections.",
        "departments": []
    }

    tasks = []

    for i, chunk in enumerate(text_chunks):
        assigned_key = API_KEYS[i % len(API_KEYS)]
        tasks.append(process_single_chunk(chunk, i, len(text_chunks), assigned_key, today))

    results = await asyncio.gather(*tasks)

    for i, standardized_data in enumerate(results):

        if not isinstance(standardized_data, dict):
            continue

        if i == 0 and standardized_data.get("document", {}).get("title"):
            master_data["document"]["title"] = standardized_data["document"].get("title", "Compliance Analysis Report")
            master_data["document"]["riskLevel"] = standardized_data["document"].get("riskLevel", "Medium")

        for new_dept in standardized_data.get("departments", []):

            if not isinstance(new_dept, dict):
                continue

            existing_dept = next((d for d in master_data["departments"] if d["name"] == new_dept["name"]), None)

            if existing_dept:
                existing_dept["tasks"].extend(new_dept.get("tasks", []))

            else:
                master_data["departments"].append(new_dept)

    if not master_data["departments"]:
        raise HTTPException(status_code=500, detail="LLM failed to extract any tasks from the document chunks.")
    
    return AnalysisResponse(**master_data)