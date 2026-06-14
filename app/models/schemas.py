from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
#  Pydantic Models — Strict schema matching the frontend dashboard
# ---------------------------------------------------------------------------

class Task(BaseModel):
    """A single compliance obligation mapped to a department."""
    id: str = Field(..., description="Unique task ID, e.g. 'IT-001', 'HR-002'")
    title: str = Field(..., description="Short, actionable task title")
    description: str = Field(..., description="Detailed description of what needs to be done")
    priority: str = Field(..., description="One of: 'critical', 'high', 'medium', 'low'")
    dueDate: str = Field(..., description="Suggested due date in ISO format YYYY-MM-DD")
    sourceClause: str = Field(..., description="The specific article/section from the document")
    completed: bool = Field(default=False, description="Whether the task is completed")


class Department(BaseModel):
    """A department with its assigned compliance tasks."""
    name: str = Field(..., description="Department name, e.g. 'Information Technology'")
    icon: str = Field(..., description="Single emoji icon for the department")
    color: str = Field(..., description="Hex color for the department, e.g. '#6366f1'")
    tasks: list[Task] = Field(..., description="List of compliance tasks for this department")


class DocumentMeta(BaseModel):
    """Metadata about the analyzed document."""
    title: str = Field(..., description="Title of the compliance document")
    type: str = Field(..., description="Type of document, e.g. 'Regulatory Compliance'")
    pages: int = Field(..., description="Number of pages in the PDF")
    analyzedAt: str = Field(..., description="ISO timestamp of analysis")
    riskLevel: str = Field(..., description="Overall risk level: 'Low', 'Medium', 'High', 'Critical'")
    complianceScore: int = Field(..., description="Initial compliance readiness score 0-100")


class AnalysisResponse(BaseModel):
    """Complete response returned to the frontend."""
    document: DocumentMeta
    summary: str = Field(..., description="Executive summary of the analysis")
    departments: list[Department] = Field(..., description="List of departments with tasks")
