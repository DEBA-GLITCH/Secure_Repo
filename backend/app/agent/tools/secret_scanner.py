# backend/app/agent/tools/secret_scanner.py
import re
from dataclasses import dataclass
from app.agent.tools.schemas import Finding, Severity, VulnCategory


@dataclass
class RegexPattern:
    name: str         # human readable name
    pattern: str      # the actual regex
    severity: Severity
    title: str        # finding title shown to user
    description: str  # explanation shown to user
    fix: str          # how to fix it


# ── Pattern library ───────────────────────────────────────────────────────────
# every pattern here is a regex that matches a known secret format
# ordered roughly by severity — most critical first

SECRET_PATTERNS: list[RegexPattern] = [

    # ── Cloud providers ───────────────────────────────────────
    RegexPattern(
        name="AWS_ACCESS_KEY",
        pattern=r"AKIA[0-9A-Z]{16}",
        severity=Severity.CRITICAL,
        title="Hardcoded AWS Access Key ID",
        description=(
            "An AWS Access Key ID was found hardcoded in the source code. "
            "This grants API access to your AWS account. Attackers scan GitHub "
            "continuously for these patterns and will find it within minutes."
        ),
        fix=(
            "1. Rotate this key immediately at aws.amazon.com/iam\n"
            "2. Move to environment variable: os.getenv('AWS_ACCESS_KEY_ID')\n"
            "3. Use IAM roles instead of access keys where possible"
        ),
    ),

    RegexPattern(
        name="AWS_SECRET_KEY",
        pattern=r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
        severity=Severity.CRITICAL,
        title="Hardcoded AWS Secret Access Key",
        description=(
            "An AWS Secret Access Key was found in source code. "
            "Combined with the Access Key ID, this gives full programmatic "
            "access to your AWS account."
        ),
        fix=(
            "1. Rotate immediately at aws.amazon.com/iam\n"
            "2. Use environment variables or AWS Secrets Manager\n"
            "3. Audit CloudTrail logs for unauthorized usage"
        ),
    ),

    # ── Payment providers ─────────────────────────────────────
    RegexPattern(
        name="STRIPE_LIVE_KEY",
        pattern=r"sk_live_[0-9a-zA-Z]{24,}",
        severity=Severity.CRITICAL,
        title="Hardcoded Stripe Live Secret Key",
        description=(
            "A live Stripe secret key was found in source code. "
            "This allows anyone to make charges, issue refunds, and access "
            "all customer payment data on your Stripe account."
        ),
        fix=(
            "1. Rotate immediately at dashboard.stripe.com/apikeys\n"
            "2. Use environment variable: os.getenv('STRIPE_SECRET_KEY')\n"
            "3. Check Stripe logs for unauthorized API calls"
        ),
    ),

    RegexPattern(
        name="STRIPE_TEST_KEY",
        pattern=r"sk_test_[0-9a-zA-Z]{24,}",
        severity=Severity.LOW,
        title="Hardcoded Stripe Test Key",
        description=(
            "A Stripe test key was found in source code. "
            "While test keys cannot make real charges, this is still bad practice "
            "and suggests live keys might be handled the same way."
        ),
        fix="Move to environment variable even for test keys. Build the habit.",
    ),

    # ── LLM / AI providers ────────────────────────────────────
    RegexPattern(
        name="OPENAI_KEY",
        pattern=r"sk-[a-zA-Z0-9]{20,}",
        severity=Severity.CRITICAL,
        title="Hardcoded OpenAI API Key",
        description=(
            "An OpenAI API key was found in source code. "
            "This allows unlimited API usage billed to your account. "
            "Leaked OpenAI keys are commonly used for large-scale abuse."
        ),
        fix=(
            "1. Rotate at platform.openai.com/api-keys\n"
            "2. Use environment variable: os.getenv('OPENAI_API_KEY')\n"
            "3. Set usage limits on your OpenAI account"
        ),
    ),

    RegexPattern(
        name="ANTHROPIC_KEY",
        pattern=r"sk-ant-[a-zA-Z0-9\-_]{40,}",
        severity=Severity.CRITICAL,
        title="Hardcoded Anthropic API Key",
        description="An Anthropic API key was found hardcoded in source code.",
        fix=(
            "1. Rotate at console.anthropic.com\n"
            "2. Use environment variable: os.getenv('ANTHROPIC_API_KEY')"
        ),
    ),

    RegexPattern(
        name="GROQ_KEY",
        pattern=r"gsk_[a-zA-Z0-9]{40,}",
        severity=Severity.CRITICAL,
        title="Hardcoded Groq API Key",
        description="A Groq API key was found hardcoded in source code.",
        fix="Rotate at console.groq.com and move to environment variable.",
    ),

    # ── Version control / CI ──────────────────────────────────
    RegexPattern(
        name="GITHUB_TOKEN",
        pattern=r"ghp_[a-zA-Z0-9]{36}",
        severity=Severity.CRITICAL,
        title="Hardcoded GitHub Personal Access Token",
        description=(
            "A GitHub PAT was found in source code. "
            "This grants access to all repositories the token owner can access."
        ),
        fix=(
            "1. Revoke at github.com/settings/tokens\n"
            "2. Use GitHub Actions secrets for CI/CD\n"
            "3. Use environment variable for local dev"
        ),
    ),

    RegexPattern(
        name="GITHUB_OAUTH_TOKEN",
        pattern=r"gho_[a-zA-Z0-9]{36}",
        severity=Severity.CRITICAL,
        title="Hardcoded GitHub OAuth Token",
        description="A GitHub OAuth token was found in source code.",
        fix="Revoke immediately at github.com/settings/tokens",
    ),

    # ── Databases ─────────────────────────────────────────────
    RegexPattern(
        name="DATABASE_URL_WITH_PASSWORD",
        # matches postgresql://user:password@host or mysql://user:pass@host
        pattern=r"(?i)(postgresql|mysql|mongodb|redis):\/\/[^:]+:[^@\s]{4,}@",
        severity=Severity.CRITICAL,
        title="Database URL with Credentials",
        description=(
            "A database connection string with embedded credentials was found. "
            "This exposes the database host, username, and password."
        ),
        fix=(
            "1. Rotate database password immediately\n"
            "2. Use environment variable: os.getenv('DATABASE_URL')\n"
            "3. Restrict DB user permissions to minimum required"
        ),
    ),

    # ── Generic patterns ──────────────────────────────────────
    RegexPattern(
        name="HARDCODED_PASSWORD",
        # matches: password = "something", password: "something"
        # (?i) = case insensitive so PASSWORD, Password etc all match
        pattern=r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']',
        severity=Severity.HIGH,
        title="Hardcoded Password",
        description=(
            "A hardcoded password was found assigned to a variable. "
            "Hardcoded passwords cannot be rotated without a code change "
            "and are visible to anyone with repo access."
        ),
        fix=(
            "Use environment variable: os.getenv('DB_PASSWORD')\n"
            "For local dev use a .env file that is gitignored"
        ),
    ),

    RegexPattern(
        name="HARDCODED_SECRET",
        pattern=r'(?i)(secret_key|secret|api_secret)\s*[=:]\s*["\'][^"\']{8,}["\']',
        severity=Severity.HIGH,
        title="Hardcoded Secret Key",
        description="A hardcoded secret key value was found in source code.",
        fix="Move to environment variable. Never hardcode secret values.",
    ),

    RegexPattern(
        name="PRIVATE_KEY_BLOCK",
        pattern=r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        severity=Severity.CRITICAL,
        title="Private Key in Source Code",
        description=(
            "A private key was found directly in source code. "
            "Private keys must NEVER be committed to version control."
        ),
        fix=(
            "1. Rotate/regenerate the key pair immediately\n"
            "2. Store private keys in a secrets manager or environment variable\n"
            "3. Add *.pem and *.key to .gitignore"
        ),
    ),

    RegexPattern(
        name="JWT_SECRET",
        pattern=r'(?i)(jwt_secret|jwt_key|token_secret)\s*[=:]\s*["\'][^"\']{8,}["\']',
        severity=Severity.HIGH,
        title="Hardcoded JWT Secret",
        description=(
            "A hardcoded JWT secret was found. "
            "Anyone with this secret can forge valid JWT tokens and "
            "impersonate any user in your system."
        ),
        fix=(
            "1. Rotate the JWT secret and invalidate all existing tokens\n"
            "2. Use environment variable: os.getenv('JWT_SECRET')\n"
            "3. Use a cryptographically random value of at least 32 bytes"
        ),
    ),
]

# compile all patterns once at import time
# compiling regex is expensive — doing it once and reusing is way faster
# than recompiling on every file scan
_COMPILED_PATTERNS: list[tuple[RegexPattern, re.Pattern]] = [
    (pattern, re.compile(pattern.pattern, re.MULTILINE))
    for pattern in SECRET_PATTERNS
]


def scan_for_secrets(file_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []

    for pattern_def, compiled_regex in _COMPILED_PATTERNS:
        matches = compiled_regex.finditer(content)

        for match in matches:
            # find the line number of this match
            # count newlines before the match start position
            line_number = content[:match.start()].count("\n") + 1

            # get surrounding code for context (3 lines around the match)
            lines = content.splitlines()
            snippet_start = max(0, line_number - 2)
            snippet_end   = min(len(lines), line_number + 2)
            raw_snippet   = "\n".join(lines[snippet_start:snippet_end])

            # mask the actual secret value in the snippet before storing
            raw_match = match.group(0)
            masked = _mask_value(raw_match)
            safe_snippet = raw_snippet.replace(raw_match, masked)

            finding = Finding(
                file_path=file_path,
                line_start=line_number,
                line_end=line_number,
                category=VulnCategory.SECRET_EXPOSURE,
                severity=pattern_def.severity,
                confidence=0.85,
                # regex matches are high confidence but not 100%
                # e.g. sk- could theoretically be a non-OpenAI key
                title=pattern_def.title,
                description=pattern_def.description,
                masked_evidence=masked,
                fix_suggestion=pattern_def.fix,
                code_snippet=safe_snippet,
                detected_by="regex",
            )
            findings.append(finding)

    return findings


def get_suspicion_score(content: str) -> float:
    # returns 0.0 to 1.0 based on how many patterns matched
    # this is what drives the routing decision in llm.py
    # more matches = higher score = goes to deep reasoning model
    hit_count = sum(
        1 for _, compiled in _COMPILED_PATTERNS
        if compiled.search(content)
    )
    # cap at 1.0 — 3+ hits = max suspicion
    return min(hit_count / 3.0, 1.0)


def _mask_value(raw: str) -> str:
    # masks a secret value for safe storage
    if len(raw) <= 8:
        return "****"
    return raw[:4] + "****" + raw[-4:]