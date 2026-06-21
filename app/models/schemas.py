import re
from pydantic import BaseModel, Field, field_validator

class Task(BaseModel):

    """A single compliance obligation mapped to a department."""

    id: str = Field(..., min_length=1, max_length=20, description="Unique task ID, e.g. 'IT-001', 'HR-002'")

    title: str = Field(..., min_length=1, max_length=500, description="Short, actionable task title")

    description: str = Field(..., min_length=1, max_length=5000, description="Detailed description of what needs to be done")

    priority: str = Field(..., description="One of: 'critical', 'high', 'medium', 'low'")

    dueDate: str = Field(..., max_length=20, description="Suggested due date in ISO format YYYY-MM-DD or empty")

    sourceClause: str = Field(..., min_length=1, max_length=500, description="The specific article/section from the document")
    
    completed: bool = Field(default=False, description="Whether the task is completed")

    @field_validator("id")
    @classmethod
    def validate_id(cls, v: str) -> str:

        """Task IDs must be alphanumeric with hyphens only (e.g. IT-001)."""
        
        cleaned = v.strip()

        if not re.match(r"^[A-Za-z0-9\-]+$", cleaned):
            raise ValueError(f"Task ID must be alphanumeric with hyphens only, got: {cleaned!r}")
        
        return cleaned
    
    @field_validator("priority")
    @classmethod
    def validate_priority(cls, v: str) -> str:

        """Priority must be one of the allowed values."""

        allowed = {"critical", "high", "medium", "low"}

        cleaned = v.strip().lower()

        if cleaned not in allowed:
            raise ValueError(f"Priority must be one of {allowed}, got: {cleaned!r}")
        return cleaned
    
    @field_validator("dueDate")
    @classmethod
    def validate_due_date(cls, v: str) -> str:
        """Due date must be YYYY-MM-DD format or empty string."""
        cleaned = v.strip()

        if cleaned and cleaned.lower() != "none":

            if not re.match(r"^\d{4}-\d{2}-\d{2}$", cleaned):
                raise ValueError(f"dueDate must be YYYY-MM-DD format or empty, got: {cleaned!r}")
            
        elif cleaned.lower() == "none":
            return ""
        
        return cleaned
    
    @field_validator("title", "description", "sourceClause")
    @classmethod
    def strip_and_sanitize_text(cls, v: str) -> str:

        """Strip leading/trailing whitespace and reject null bytes."""

        cleaned = v.strip()

        if "\x00" in cleaned:
            raise ValueError("Null bytes are not allowed in text fields")
        return cleaned
    
class Department(BaseModel):

    """A department with its assigned compliance tasks."""

    name: str = Field(..., min_length=1, max_length=200, description="Department name, e.g. 'Information Technology'")

    icon: str = Field(..., min_length=1, max_length=10, description="Single emoji icon for the department")

    color: str = Field(..., max_length=20, description="Hex color for the department, e.g. '#6366f1'")

    tasks: list[Task] = Field(..., max_length=100, description="List of compliance tasks for this department")

    @field_validator("color")
    @classmethod
    def validate_color(cls, v: str) -> str:
        """Color must be a valid hex color code."""

        cleaned = v.strip()

        if not re.match(r"^#[0-9a-fA-F]{3,8}$", cleaned):
            raise ValueError(f"Color must be a valid hex code (e.g. #6366f1), got: {cleaned!r}")
        return cleaned
    
    @field_validator("name")
    @classmethod
    def sanitize_name(cls, v: str) -> str:

        """Strip and reject null bytes in department names."""

        cleaned = v.strip()

        if "\x00" in cleaned:
            raise ValueError("Null bytes are not allowed in department names")
        return cleaned
    
class DocumentMeta(BaseModel):
    
    """Metadata about the analyzed document."""

    title: str = Field(..., min_length=1, max_length=500, description="Title of the compliance document")

    type: str = Field(..., min_length=1, max_length=200, description="Type of document, e.g. 'Regulatory Compliance'")

    pages: int = Field(..., ge=0, le=100000, description="Number of pages in the PDF")

    analyzedAt: str = Field(..., max_length=50, description="ISO timestamp of analysis")

    riskLevel: str = Field(..., description="Overall risk level: 'Low', 'Medium', 'High', 'Critical'")

    complianceScore: int = Field(..., ge=0, le=100, description="Initial compliance readiness score 0-100")

    @field_validator("riskLevel")
    @classmethod
    def validate_risk_level(cls, v: str) -> str:

        """Risk level must be one of the allowed values."""

        allowed = {"Low", "Medium", "High", "Critical"}

        cleaned = v.strip().capitalize()

        if cleaned not in allowed:
            raise ValueError(f"riskLevel must be one of {allowed}, got: {cleaned!r}")
        return cleaned
    
    @field_validator("title", "type")
    @classmethod
    def sanitize_doc_text(cls, v: str) -> str:

        """Strip and reject null bytes."""

        cleaned = v.strip()

        if "\x00" in cleaned:
            raise ValueError("Null bytes are not allowed in document metadata")
        return cleaned
class AnalysisResponse(BaseModel):

    """Complete response returned to the frontend."""

    document: DocumentMeta

    summary: str = Field(..., min_length=1, max_length=10000, description="Executive summary of the analysis")

    departments: list[Department] = Field(..., max_length=50, description="List of departments with tasks")
