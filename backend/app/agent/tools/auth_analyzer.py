# backend/app/agent/tools/auth_analyzer.py
import re
import ast
from dataclasses import dataclass, field
from app.agent.tools.schemas import Finding, Severity, VulnCategory


@dataclass
class AuthPattern:
    name: str
    pattern: str
    category: VulnCategory
    severity: Severity
    title: str
    description: str
    fix: str
    languages: list[str] = field(default_factory=lambda: ["any"])


AUTH_PATTERNS: list[AuthPattern] = [

    # ── Weak Hashing ──────────────────────────────────────────────────────────
    AuthPattern(
        name="MD5_FOR_PASSWORD",
        pattern=r'(?i)md5\s*\(.{0,60}(password|passwd|pwd|secret)',
        category=VulnCategory.CRYPTO_FAILURE,
        severity=Severity.CRITICAL,
        title="MD5 Used for Password Hashing",
        description=(
            "MD5 is being used to hash what appears to be a password. "
            "MD5 is a broken algorithm — entire rainbow tables exist for MD5 hashes. "
            "An attacker who gets your database can crack every password in minutes."
        ),
        fix=(
            "Use bcrypt, argon2, or scrypt for password hashing:\n"
            "  from passlib.context import CryptContext\n"
            "  pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')\n"
            "  hashed = pwd_context.hash(password)\n"
            "  verified = pwd_context.verify(password, hashed)"
        ),
    ),

    AuthPattern(
        name="SHA1_FOR_PASSWORD",
        pattern=r'(?i)sha1\s*\(.{0,60}(password|passwd|pwd|secret)',
        category=VulnCategory.CRYPTO_FAILURE,
        severity=Severity.CRITICAL,
        title="SHA1 Used for Password Hashing",
        description=(
            "SHA1 is being used to hash a password. "
            "SHA1 is cryptographically broken and unsuitable for passwords. "
            "It has no salt, no work factor, and is trivially crackable."
        ),
        fix="Use bcrypt or argon2id for password hashing. Never use SHA1 or MD5.",
    ),

    AuthPattern(
        name="WEAK_HASH_IMPORT",
        # catches: hashlib.md5(), hashlib.sha1() — common pattern
        pattern=r'hashlib\.(md5|sha1)\s*\(',
        category=VulnCategory.CRYPTO_FAILURE,
        severity=Severity.MEDIUM,
        title="Weak Hash Algorithm (MD5/SHA1)",
        description=(
            "hashlib.md5() or hashlib.sha1() is being used. "
            "While these have legitimate uses (checksums, non-security hashing), "
            "if used for passwords, tokens, or security purposes they are dangerously weak."
        ),
        fix=(
            "For passwords: use bcrypt or argon2\n"
            "For security tokens: use hashlib.sha256() minimum\n"
            "For checksums only: MD5/SHA1 are acceptable"
        ),
    ),

    # ── JWT Issues ────────────────────────────────────────────────────────────
    AuthPattern(
        name="JWT_NO_EXPIRY",
        # JWT encode without 'exp' in the payload
        pattern=r'jwt\.(encode|decode)\s*\([^)]{0,300}\)',
        category=VulnCategory.BROKEN_AUTH,
        severity=Severity.HIGH,
        title="JWT Token May Lack Expiry",
        description=(
            "A JWT token is being created or decoded. "
            "If the payload does not include an 'exp' (expiration) claim, "
            "stolen tokens are valid forever — there is no way to invalidate them "
            "short of rotating your signing secret."
        ),
        fix=(
            "Always include exp in JWT payloads:\n"
            "  from datetime import datetime, timedelta\n"
            "  payload = {\n"
            "      'sub': user_id,\n"
            "      'exp': datetime.utcnow() + timedelta(hours=1),\n"
            "  }\n"
            "  token = jwt.encode(payload, SECRET, algorithm='HS256')"
        ),
    ),

    AuthPattern(
        name="JWT_NONE_ALGORITHM",
        # 'none' algorithm completely bypasses signature verification
        pattern=r'(?i)algorithm[s]?\s*[=:]\s*["\']none["\']',
        category=VulnCategory.BROKEN_AUTH,
        severity=Severity.CRITICAL,
        title="JWT 'none' Algorithm Accepted",
        description=(
            "The JWT 'none' algorithm is explicitly set or accepted. "
            "The 'none' algorithm means the token has NO signature — "
            "anyone can forge tokens and impersonate any user. "
            "This is a well-known critical JWT vulnerability."
        ),
        fix=(
            "Never accept 'none' as a valid algorithm.\n"
            "Always explicitly specify allowed algorithms:\n"
            "  jwt.decode(token, SECRET, algorithms=['HS256'])\n"
            "  # NOT: algorithms=['HS256', 'none']"
        ),
    ),

    # ── Insecure Defaults ─────────────────────────────────────────────────────
    AuthPattern(
        name="DEBUG_TRUE",
        pattern=r'(?i)DEBUG\s*=\s*True',
        category=VulnCategory.DEBUG_EXPOSURE,
        severity=Severity.HIGH,
        title="DEBUG Mode Enabled",
        description=(
            "DEBUG=True is set which may be present in production config. "
            "Debug mode exposes full stack traces to users including:\n"
            "- Internal file paths\n"
            "- Environment variables\n"
            "- Source code snippets\n"
            "- Database query details"
        ),
        fix=(
            "Ensure DEBUG is False in production:\n"
            "  DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'\n"
            "Never hardcode DEBUG=True in any file that gets deployed."
        ),
    ),

    AuthPattern(
        name="VERIFY_FALSE",
        # SSL verification disabled — common lazy dev shortcut
        pattern=r'verify\s*=\s*False',
        category=VulnCategory.CRYPTO_FAILURE,
        severity=Severity.HIGH,
        title="SSL Certificate Verification Disabled",
        description=(
            "SSL certificate verification is disabled (verify=False). "
            "This makes HTTPS connections completely insecure — your app will "
            "accept any certificate including self-signed and expired ones. "
            "This enables man-in-the-middle attacks where an attacker can "
            "intercept all traffic between your app and the target server."
        ),
        fix=(
            "Remove verify=False entirely — it should never reach production.\n"
            "If you need to connect to a server with a custom CA:\n"
            "  requests.get(url, verify='/path/to/ca-bundle.crt')\n"
            "For local dev with self-signed certs use a proper local CA."
        ),
    ),

    AuthPattern(
        name="HARDCODED_ADMIN_CREDS",
        pattern=r'(?i)(admin|root|superuser).{0,30}(password|passwd|pwd).{0,20}["\'][^"\']{3,}["\']',
        category=VulnCategory.BROKEN_AUTH,
        severity=Severity.CRITICAL,
        title="Hardcoded Admin Credentials",
        description=(
            "Hardcoded admin or root credentials were found in source code. "
            "Default credentials are the first thing attackers try. "
            "This gives immediate full access to anyone who reads the code."
        ),
        fix=(
            "Remove hardcoded credentials immediately.\n"
            "For initial admin setup use environment variables:\n"
            "  ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')\n"
            "Rotate the password if it was ever committed."
        ),
    ),

    # ── Missing Authorization ─────────────────────────────────────────────────
    AuthPattern(
        name="IDOR_DIRECT_ID",
        # route with {id} or /{id} but no ownership check pattern nearby
        pattern=r'(?i)(get|fetch|find|query).{0,60}(by_id|get_by_id|filter_by\s*\(\s*id)',
        category=VulnCategory.BROKEN_AUTHZ,
        severity=Severity.MEDIUM,
        title="Potential IDOR — Direct Object Reference Without Visible Auth Check",
        description=(
            "A database lookup by ID was found without a visible ownership "
            "or permission check nearby. If the ID comes from user input and "
            "there is no check that the requesting user owns this resource, "
            "any user can access any other user's data by guessing IDs.\n\n"
            "Example: GET /api/invoice/1234 — can user A access invoice 5678?"
        ),
        fix=(
            "Always verify ownership before returning data:\n"
            "  record = db.query(Invoice).filter_by(id=invoice_id).first()\n"
            "  if record.user_id != current_user.id:\n"
            "      raise HTTPException(status_code=403, detail='forbidden')\n"
            "  return record"
        ),
    ),

    # ── Sensitive Data in Logs ────────────────────────────────────────────────
    AuthPattern(
        name="PASSWORD_IN_LOG",
        pattern=r'(?i)(log|print|logger)\s*[\.\(].{0,60}(password|passwd|token|secret|key)',
        category=VulnCategory.SENSITIVE_LOGGING,
        severity=Severity.HIGH,
        title="Sensitive Data Logged",
        description=(
            "A logging or print statement appears to include a password, "
            "token, or secret. Log files are often stored insecurely, "
            "shipped to third-party log aggregators, and retained long-term. "
            "Secrets in logs can be exposed long after the original secret is rotated."
        ),
        fix=(
            "Never log sensitive values:\n"
            "  # WRONG: logger.info(f'user login attempt password={password}')\n"
            "  # RIGHT: logger.info(f'user login attempt user={username}')\n"
            "If you must log for debugging, mask the value:\n"
            "  masked = password[:2] + '****'"
        ),
    ),

    # ── Mass Assignment ───────────────────────────────────────────────────────
    AuthPattern(
        name="MASS_ASSIGNMENT_DICT",
        # **request.dict() or **body.dict() passed directly to DB model
        pattern=r'\*\*(request|req|body|data|payload)\s*[\.\(]',
        category=VulnCategory.MASS_ASSIGNMENT,
        severity=Severity.HIGH,
        title="Potential Mass Assignment Vulnerability",
        description=(
            "A request body is being unpacked with ** directly into what may "
            "be a database model or update call. "
            "An attacker can add extra fields to the request body "
            "(e.g. is_admin=true, role='superuser') and have them written "
            "to the database if not explicitly filtered."
        ),
        fix=(
            "Explicitly whitelist allowed fields:\n"
            "  # WRONG: User(**request.dict())\n"
            "  # RIGHT:\n"
            "  allowed = {'name', 'email', 'bio'}\n"
            "  safe_data = {k: v for k, v in request.dict().items() if k in allowed}\n"
            "  User(**safe_data)\n"
            "Or use Pydantic models with explicit fields to control what's accepted."
        ),
    ),
]

_COMPILED: list[tuple[AuthPattern, re.Pattern]] = [
    (p, re.compile(p.pattern, re.MULTILINE | re.DOTALL))
    for p in AUTH_PATTERNS
]


def analyze_auth(file_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []

    for pattern_def, compiled in _COMPILED:
        matches = list(compiled.finditer(content))
        if not matches:
            continue

        first_match = matches[0]
        line_number  = content[:first_match.start()].count("\n") + 1

        lines         = content.splitlines()
        snippet_start = max(0, line_number - 2)
        snippet_end   = min(len(lines), line_number + 2)
        snippet       = "\n".join(lines[snippet_start:snippet_end])

        title = pattern_def.title
        if len(matches) > 1:
            title = f"{pattern_def.title} ({len(matches)} occurrences)"

        findings.append(Finding(
            file_path=file_path,
            line_start=line_number,
            line_end=line_number,
            category=pattern_def.category,
            severity=pattern_def.severity,
            confidence=0.8,
            title=title,
            description=pattern_def.description,
            masked_evidence=first_match.group(0)[:80],
            fix_suggestion=pattern_def.fix,
            code_snippet=snippet,
            detected_by="regex",
        ))

    # Python-specific AST checks
    ext = file_path.split(".")[-1].lower()
    if ext == "py":
        findings.extend(_ast_auth_checks(file_path, content))

    return findings


def _ast_auth_checks(file_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []

    for node in ast.walk(tree):
        # detect: except: pass — swallowing ALL exceptions
        # commonly hides auth failures silently
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                # bare except: catches everything including auth errors
                body_is_pass = (
                    len(node.body) == 1 and
                    isinstance(node.body[0], ast.Pass)
                )
                if body_is_pass:
                    findings.append(Finding(
                        file_path=file_path,
                        line_start=node.lineno,
                        line_end=node.lineno,
                        category=VulnCategory.BROKEN_AUTH,
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        title="Silent Exception Swallowing (except: pass)",
                        description=(
                            "A bare 'except: pass' was found which silently swallows "
                            "ALL exceptions. If this wraps an authentication or "
                            "authorization check, failures are silently ignored "
                            "and execution continues as if the check passed."
                        ),
                        masked_evidence=f"except: pass at line {node.lineno}",
                        fix_suggestion=(
                            "Always handle specific exceptions:\n"
                            "  try:\n"
                            "      verify_token(token)\n"
                            "  except InvalidTokenError:\n"
                            "      raise HTTPException(401, 'invalid token')\n"
                            "Never use bare except: pass around security checks."
                        ),
                        detected_by="ast",
                    ))

    return findings


def get_auth_suspicion_score(content: str) -> float:
    hit_count = sum(
        1 for _, compiled in _COMPILED
        if compiled.search(content)
    )
    return min(hit_count / 3.0, 1.0)