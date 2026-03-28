# backend/app/db/models.py
import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import (
    Column, String, Text, Float,
    Integer, DateTime, ForeignKey,
    Enum, Boolean
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, relationship


# all models inherit from this Base
# SQLAlchemy uses it to track every table in your schema
class Base(DeclarativeBase):
    pass


# ── Enums ─────────────────────────────────────────────────────────────────────
# str + PyEnum means the value IS the string
# so ScanStatus.PENDING == "pending" is True
# this matters when serializing to JSON — you get "pending" not "<ScanStatus.PENDING>"

class ScanStatus(str, PyEnum):
    PENDING   = "pending"    # job created, sitting in Redis queue
    RUNNING   = "running"    # worker picked it up, scanning now
    COMPLETED = "completed"  # all findings aggregated, report ready
    FAILED    = "failed"     # something crashed, check error_message


class Severity(str, PyEnum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class VulnCategory(str, PyEnum):
    SECRET_EXPOSURE     = "secret_exposure"
    SQL_INJECTION       = "sql_injection"
    COMMAND_INJECTION   = "command_injection"
    PROMPT_INJECTION    = "prompt_injection"
    BROKEN_AUTH         = "broken_auth"
    BROKEN_AUTHZ        = "broken_authz"
    CRYPTO_FAILURE      = "crypto_failure"
    RATE_LIMIT_MISSING  = "rate_limit_missing"
    MASS_ASSIGNMENT     = "mass_assignment"
    INSECURE_DESERIAL   = "insecure_deserialization"
    PATH_TRAVERSAL      = "path_traversal"
    SSRF                = "ssrf"
    REDOS               = "redos"
    DEBUG_EXPOSURE      = "debug_exposure"
    MISSING_HEADERS     = "missing_headers"
    SENSITIVE_LOGGING   = "sensitive_logging"
    INPUT_VALIDATION    = "input_validation"
    AI_SPECIFIC         = "ai_specific"
    OUTDATED_DEPENDENCY = "outdated_dependency"


# ── Models ────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    github_id    = Column(String, unique=True, nullable=False)
    # github_id is the stable identifier — username can change, this never does

    username     = Column(String, nullable=False)
    email        = Column(String, nullable=True)
    # email is nullable — GitHub lets users keep email private

    avatar_url   = Column(String, nullable=True)
    access_token = Column(String, nullable=False)
    # this is the GitHub OAuth token we use to call GitHub API on their behalf
    # in production you'd encrypt this at rest — for now we store it as-is

    created_at   = Column(DateTime, default=datetime.utcnow)

    # one user → many scan jobs
    scans = relationship("ScanJob", back_populates="user")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id       = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    repo_url      = Column(String, nullable=False)
    repo_name     = Column(String, nullable=False)
    # repo_name = "owner/repo" format e.g. "torvalds/linux"

    commit_sha    = Column(String, nullable=False)
    # THIS is the cache key — not the URL
    # same SHA = byte for byte identical code = safe to return cached result

    is_private    = Column(Boolean, default=False)
    status        = Column(Enum(ScanStatus), default=ScanStatus.PENDING)

    total_files   = Column(Integer, default=0)
    # how many files exist in the repo

    scanned_files = Column(Integer, default=0)
    # how many we actually analyzed (after pre-filter)
    # total_files - scanned_files = files skipped (images, lock files etc)

    error_message = Column(Text, nullable=True)
    # only populated when status = FAILED
    # stores the exception message so user knows what went wrong

    started_at    = Column(DateTime, nullable=True)
    completed_at  = Column(DateTime, nullable=True)
    created_at    = Column(DateTime, default=datetime.utcnow)

    user     = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan_job")


class Finding(Base):
    __tablename__ = "findings"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_job_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False)

    # ── where is the issue ────────────────────────────────────────
    file_path  = Column(String, nullable=False)
    # "src/api/routes/users.py"

    line_start = Column(Integer, nullable=True)
    line_end   = Column(Integer, nullable=True)
    # nullable because some findings are file-level not line-level
    # e.g. "this entire file has no rate limiting"

    # ── what is the issue ─────────────────────────────────────────
    category   = Column(Enum(VulnCategory), nullable=False)
    severity   = Column(Enum(Severity), nullable=False)

    confidence = Column(Float, nullable=False)
    # 0.0 to 1.0 — how sure is the LLM about this finding
    # 0.9 = very sure, 0.4 = possible but uncertain
    # lets the frontend show "high confidence" vs "needs review"

    # ── what to show the user ─────────────────────────────────────
    title           = Column(String, nullable=False)
    # "Hardcoded Stripe API Key"

    description     = Column(Text, nullable=False)
    # "A live Stripe secret key was found hardcoded in config.py.
    #  Anyone with read access to this repo can make charges."

    masked_evidence = Column(String, nullable=True)
    # "sk_live_****abc123"
    # NEVER store the full raw secret — this is what you decided in Q5
    # enough info to locate and rotate it, not enough to weaponize it

    fix_suggestion  = Column(Text, nullable=False)
    # "Move this to an environment variable. Use os.getenv('STRIPE_SECRET_KEY').
    #  Rotate the key immediately at dashboard.stripe.com/apikeys"

    code_snippet    = Column(Text, nullable=True)
    # the 3-5 lines of code around the issue
    # sanitized — secrets masked before storing

    detected_by = Column(String, nullable=False)
    # "regex" | "ast" | "llm_groq" | "llm_deepseek"
    # tells you which layer of the pipeline caught it
    # useful for tuning — if LLM catches something regex should have, improve regex

    created_at = Column(DateTime, default=datetime.utcnow)

    scan_job = relationship("ScanJob", back_populates="findings")