import os
from sqlalchemy import create_engine, Column, String, Text, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base

# ---------------------------------------------------------------------------
#  Database Configuration
# ---------------------------------------------------------------------------

# Use DATABASE_URL from environment if available (for PostgreSQL in production).
# Fallback to local SQLite database for easy local testing.
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./compliance.db")

# SQLite requires check_same_thread=False, but PostgreSQL does not.
connect_args = {"check_same_thread": False} if SQLALCHEMY_DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args=connect_args
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# ---------------------------------------------------------------------------
#  Database Models
# ---------------------------------------------------------------------------

class ComplianceTask(Base):
    __tablename__ = "compliance_tasks"

    id = Column(String, primary_key=True, index=True)
    department_name = Column(String, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    priority = Column(String, nullable=False)
    due_date = Column(String)
    source_clause = Column(String)
    completed = Column(Boolean, default=False)

# ---------------------------------------------------------------------------
#  Dependency Generator
# ---------------------------------------------------------------------------

def get_db():
    """
    Yields a database session to be used in FastAPI route dependencies.
    Ensures the connection is properly closed after the request completes.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()