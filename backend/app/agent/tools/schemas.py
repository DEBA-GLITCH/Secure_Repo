# backend/app/agent/tools/schemas.py
from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum


# mirrors the DB enums exactly
# but these are Pydantic models — used in memory during agent execution
# the DB models (SQLAlchemy) are only used when reading/writing to postgres

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class VulnCategory(str, Enum):
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


class Finding(BaseModel):
    # ── location ──────────────────────────────────────────────
    file_path: str = Field(
        description="relative path to the file e.g. src/api/routes/users.py"
    )
    line_start: Optional[int] = Field(
        default=None,
        description="line number where the issue starts"
    )
    line_end: Optional[int] = Field(
        default=None,
        description="line number where the issue ends"
    )

    # ── classification ────────────────────────────────────────
    category: VulnCategory = Field(
        description="type of vulnerability"
    )
    severity: Severity = Field(
        description="how critical is this issue"
    )
    confidence: float = Field(
        ge=0.0, le=1.0,
        # ge = greater than or equal, le = less than or equal
        # pydantic validates this automatically — 1.5 would raise an error
        description="0.0 to 1.0 — how confident is the detection"
    )

    # ── what to show the user ─────────────────────────────────
    title: str = Field(
        description="short title e.g. 'Hardcoded Stripe API Key'"
    )
    description: str = Field(
        description="full explanation of the issue and why it's dangerous"
    )
    masked_evidence: Optional[str] = Field(
        default=None,
        description="the evidence with secret values masked e.g. sk_live_****abc"
        # NEVER put the raw secret here — this is the Q5 decision enforced in code
    )
    fix_suggestion: str = Field(
        description="concrete steps to fix this issue"
    )
    code_snippet: Optional[str] = Field(
        default=None,
        description="3-5 lines of sanitized code around the issue"
    )

    # ── detection metadata ────────────────────────────────────
    detected_by: str = Field(
        description="which layer caught this: regex | ast | llm_groq | llm_deepseek"
    )

    def mask_secret(self, raw_value: str) -> str:
        # utility method — call this before setting masked_evidence
        # takes "sk_live_abc123xyz" → "sk_live_****xyz"
        if len(raw_value) <= 8:
            return "****"
        # show first 4 and last 4 chars, mask everything in between
        return raw_value[:4] + "****" + raw_value[-4:]


class FileAnalysisResult(BaseModel):
    # what the pre-filter produces for each file
    # before the LLM even sees it
    file_path: str
    content: str
    suspicion_score: float = Field(ge=0.0, le=1.0)
    # suspicion_score drives the routing decision in llm.py
    # 0.0 = looks totally clean
    # 1.0 = screaming red flags from regex/AST

    regex_hits: list[str] = Field(default_factory=list)
    # list of regex pattern names that matched
    # e.g. ["STRIPE_KEY", "HARDCODED_PASSWORD"]

    ast_hits: list[str] = Field(default_factory=list)
    # list of AST pattern names that matched
    # e.g. ["SQL_STRING_CONCAT", "OS_SYSTEM_CALL"]

    language: Optional[str] = None
    # detected programming language — used to pick the right AST parser


class ScanSummary(BaseModel):
    # the final output of the entire agent pipeline
    repo_url: str
    commit_sha: str
    total_files_scanned: int
    findings: list[Finding]

    # convenience computed fields
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def by_category(self) -> dict[str, int]:
        # groups findings by category for the report
        # e.g. {"sql_injection": 3, "secret_exposure": 1}
        counts: dict[str, int] = {}
        for f in self.findings:
            key = f.category.value
            counts[key] = counts.get(key, 0) + 1
        return counts