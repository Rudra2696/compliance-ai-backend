import json
from datetime import datetime

from fastapi import HTTPException
from openai import OpenAI

from app.core.config import XAI_API_KEY, XAI_MODEL, logger
from app.models.schemas import AnalysisResponse

# ---------------------------------------------------------------------------
#  LLM Pipeline — Obligation Extraction & Department Mapping
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are ComplianceAI, an expert regulatory compliance analyst. Your task is to analyze a compliance/policy document and extract all actionable obligations.

## YOUR INSTRUCTIONS:

1. **Read the entire document carefully.** Identify every regulatory obligation, requirement, mandate, or recommended action.

2. **For each obligation, create a task** with:
   - A clear, actionable title (imperative form, e.g., "Implement encryption for data at rest")
   - A detailed description explaining what must be done, by whom, and how
   - A priority level: "critical" (legal risk / fines), "high" (operational risk), "medium" (best practice), or "low" (nice to have)
   - A suggested due date (YYYY-MM-DD format) based on urgency. Use dates within 1-6 months from today.
   - The exact source clause, article, or section reference from the document

3. **Dynamically identify the departments, boards, teams, or roles** that are actually responsible for compliance in this specific document — do NOT use a fixed or predefined list of departments. Read the document for organizational references (named departments, committees, boards, governing bodies, job titles, or functional units) and group the extracted tasks accordingly. For each department/group you identify:
   - Use a clear, professional name that reflects the document's own terminology where possible (e.g., "Clinical Operations", "School Administration", "Board of Directors", "Information Security")
   - Assign a relevant, contextual emoji as the `icon` that visually represents that group's function
   - Assign a distinct, professional hex color as the `color` field (e.g., "#6366f1") — choose colors that are visually distinguishable from one another across all departments in the response
   - Map each extracted task to the SINGLE most relevant department/group based on who would realistically own and execute it

4. **Generate unique task IDs** by deriving a 3-4 letter uppercase abbreviation from each dynamically identified department/group name, followed by a hyphen and a zero-padded sequence number (format: ABBR-NNN). For example: "Clinical Operations" → CLIN-001, CLIN-002; "School Administration" → SCH-001, SCH-002; "Board of Directors" → BOD-001. Use the SAME abbreviation consistently for every task within that department, and number tasks sequentially starting from 001 within each department.

5. **Assess the overall document** and provide:
   - A document title (inferred from the content)
   - The document type (e.g., "Regulatory Compliance", "Internal Policy", "Industry Standard")
   - An overall risk level: "Low", "Medium", "High", or "Critical"
   - An initial compliance score (0-100) representing how prepared the average organization would be
   - An executive summary (2-3 sentences) of the key findings

## OUTPUT FORMAT:

You MUST respond with ONLY valid JSON. No markdown, no code fences, no explanations. Just the JSON object.
The JSON must match this exact structure:

{
  "document": {
    "title": "string",
    "type": "string",
    "pages": <number>,
    "analyzedAt": "<ISO 8601 timestamp>",
    "riskLevel": "Low|Medium|High|Critical",
    "complianceScore": <0-100>
  },
  "summary": "string",
  "departments": [
    {
      "name": "string",
      "icon": "string (emoji)",
      "color": "string (hex)",
      "tasks": [
        {
          "id": "string",
          "title": "string",
          "description": "string",
          "priority": "critical|high|medium|low",
          "dueDate": "YYYY-MM-DD",
          "sourceClause": "string",
          "completed": false
        }
      ]
    }
  ]
}

## IMPORTANT RULES:
- Extract AT LEAST 10 obligations if the document is substantive.
- Each department should have at least 1 task if relevant obligations exist.
- Every task MUST reference a specific clause/article/section from the document.
- Due dates should be realistic and staggered (not all the same date).
- The "completed" field must always be false.
- Do NOT include any text outside the JSON object.
"""


def analyze_with_llm(document_text: str, page_count: int) -> AnalysisResponse:
    if not XAI_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="XAI_API_KEY environment variable is not set. "
                   "Set it to your xAI API key to enable LLM analysis."
        )

    client = OpenAI(api_key=XAI_API_KEY, base_url="https://api.x.ai/v1")

    today = datetime.now().strftime("%Y-%m-%d")
    user_message = (
        f"Today's date is {today}. The document has {page_count} pages.\n\n"
        f"DOCUMENT TEXT:\n\n{document_text}"
    )

    logger.info(f"Sending {len(user_message)} chars to {XAI_MODEL}...")

    try:
        response = client.chat.completions.create(
            model=XAI_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            temperature=0.2,       # Low temperature for consistent, structured output
            max_tokens=8000,       # Allow lengthy responses for many obligations
            response_format={"type": "json_object"},  # Enforce JSON output mode
        )

        raw_content = response.choices[0].message.content
        logger.info(f"LLM response received: {len(raw_content)} chars")

        # Parse the JSON response
        parsed = json.loads(raw_content)

        # Inject actual page count and timestamp
        parsed["document"]["pages"] = page_count
        parsed["document"]["analyzedAt"] = datetime.now().isoformat()

        # Validate against our Pydantic schema
        result = AnalysisResponse(**parsed)
        return result

    except json.JSONDecodeError as e:
        logger.error(f"LLM returned invalid JSON: {e}")
        raise HTTPException(status_code=500, detail="LLM returned invalid JSON. Please retry.")
    except Exception as e:
        # Keep internal logs detailed, but send a generic response to the client
        logger.error(f"LLM analysis failed: {e}")
        raise HTTPException(status_code=500, detail="An internal server error occurred")


# ---------------------------------------------------------------------------
#  Alternative: LangChain Pipeline (drop-in replacement for analyze_with_llm)
# ---------------------------------------------------------------------------

def analyze_with_langchain(document_text: str, page_count: int) -> AnalysisResponse:
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import SystemMessage, HumanMessage
    from langchain_core.output_parsers import JsonOutputParser

    llm = ChatOpenAI(
        model=XAI_MODEL,
        temperature=0.2,
        max_tokens=8000,
        api_key=XAI_API_KEY,
        base_url="https://api.x.ai/v1",
        model_kwargs={"response_format": {"type": "json_object"}},
    )

    parser = JsonOutputParser(pydantic_object=AnalysisResponse)

    today = datetime.now().strftime("%Y-%m-%d")

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=(
            f"Today's date is {today}. The document has {page_count} pages.\n\n"
            f"DOCUMENT TEXT:\n\n{document_text}"
        )),
    ]

    response = llm.invoke(messages)
    parsed = parser.parse(response.content)

    # Inject metadata
    parsed["document"]["pages"] = page_count
    parsed["document"]["analyzedAt"] = datetime.now().isoformat()

    return AnalysisResponse(**parsed)